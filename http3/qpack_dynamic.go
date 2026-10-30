package http3

// RFC 9204 dynamic QPACK state. Browser choices are supplied by JSON policy;
// wire integer limits, table accounting and reference lifetime are invariants.
import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2/hpack"
)

const qpackIntegerLimit uint64 = 1<<62 - 1
const qpackTableSafetyLimit uint64 = 1 << 20
const qpackBlockedSafetyLimit uint64 = 1024

var errQPACKWire = errors.New("invalid QPACK representation")

type qpackWireError struct {
	code ErrCode
	err  error
}

func (e *qpackWireError) Error() string          { return e.err.Error() }
func (e *qpackWireError) Unwrap() error          { return e.err }
func qpackFailure(code ErrCode, err error) error { return &qpackWireError{code, err} }

func readQPACKInt(r *bufio.Reader, first byte, bits uint8) (uint64, error) {
	mask := uint64(1<<bits) - 1
	n := uint64(first) & mask
	if n < mask {
		return n, nil
	}
	for shift := uint(0); shift < 63; shift += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v := uint64(b & 127)
		if v > (qpackIntegerLimit-n)>>shift {
			return 0, errQPACKWire
		}
		n += v << shift
		if b&128 == 0 {
			return n, nil
		}
	}
	return 0, errQPACKWire
}
func readQPACKString(r *bufio.Reader, first byte, bits uint8, huffman byte, limit uint64) (string, error) {
	n, err := readQPACKInt(r, first, bits)
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", errQPACKWire
	}
	p := make([]byte, int(n))
	if _, err = io.ReadFull(r, p); err != nil {
		return "", err
	}
	if first&huffman == 0 {
		return string(p), nil
	}
	s, err := hpack.HuffmanDecodeToString(p)
	if uint64(len(s)) > limit {
		return "", errQPACKWire
	}
	return s, err
}
func qpackStatic(index uint64) (qpack.HeaderField, error) {
	b := appendQPACKInt([]byte{0, 0}, 6, 0xc0, index)
	return qpack.NewDecoder().Decode(b)()
}

type dynamicEntry struct {
	id    uint64
	field qpack.HeaderField
}

func entrySize(f qpack.HeaderField) uint64 { return uint64(len(f.Name)) + uint64(len(f.Value)) + 32 }

type dynamicTable struct {
	entries                  []dynamicEntry
	inserted, size, capacity uint64
}

func (t *dynamicTable) absolute(id uint64) (qpack.HeaderField, error) {
	if len(t.entries) == 0 || id < t.entries[0].id || id >= t.inserted {
		return qpack.HeaderField{}, errQPACKWire
	}
	return t.entries[id-t.entries[0].id].field, nil
}
func (t *dynamicTable) relative(index uint64) (qpack.HeaderField, error) {
	if index >= t.inserted {
		return qpack.HeaderField{}, errQPACKWire
	}
	return t.absolute(t.inserted - index - 1)
}
func (t *dynamicTable) evict(size uint64, can func(uint64) bool) bool {
	if size > t.capacity {
		return false
	}
	// Check first; failed reservations must not evict a partial prefix.
	remaining := t.size
	for _, e := range t.entries {
		if remaining+size <= t.capacity {
			break
		}
		if can != nil && !can(e.id) {
			return false
		}
		remaining -= entrySize(e.field)
	}
	for t.size+size > t.capacity {
		e := t.entries[0]
		t.size -= entrySize(e.field)
		t.entries[0] = dynamicEntry{}
		t.entries = t.entries[1:]
	}
	return true
}
func (t *dynamicTable) insert(f qpack.HeaderField, can func(uint64) bool) bool {
	size := entrySize(f)
	if t.inserted == qpackIntegerLimit || !t.evict(size, can) {
		return false
	}
	t.entries = append(t.entries, dynamicEntry{t.inserted, f})
	t.inserted++
	t.size += size
	return true
}

type dynamicQPACKDecoder struct {
	mu                              sync.Mutex
	table                           dynamicTable
	maximum, blockedLimit, reported uint64
	feedbackMode                    string
	blocked                         map[uint64]bool
	changed                         chan struct{}
	send                            func([]byte) error
}

func newDynamicQPACKDecoder(maximum, blocked uint64, send func([]byte) error) *dynamicQPACKDecoder {
	return &dynamicQPACKDecoder{maximum: maximum, blockedLimit: blocked, blocked: make(map[uint64]bool), changed: make(chan struct{}), send: send}
}
func (d *dynamicQPACKDecoder) instruction(r *bufio.Reader) error {
	first, err := r.ReadByte()
	if err != nil {
		return err
	}
	var f qpack.HeaderField
	switch {
	case first&0x80 != 0:
		index, e := readQPACKInt(r, first, 6)
		if e != nil {
			return e
		}
		d.mu.Lock()
		if first&0x40 != 0 {
			f, e = qpackStatic(index)
		} else {
			f, e = d.table.relative(index)
		}
		d.mu.Unlock()
		if e != nil {
			return e
		}
		b, e := r.ReadByte()
		if e != nil {
			return e
		}
		f.Value, e = readQPACKString(r, b, 7, 0x80, d.maximum)
		if e != nil {
			return e
		}
	case first&0xc0 == 0x40:
		f.Name, err = readQPACKString(r, first, 5, 0x20, d.maximum)
		if err != nil {
			return err
		}
		b, e := r.ReadByte()
		if e != nil {
			return e
		}
		f.Value, e = readQPACKString(r, b, 7, 0x80, d.maximum)
		if e != nil {
			return e
		}
	case first&0xe0 == 0x20:
		capacity, e := readQPACKInt(r, first, 5)
		if e != nil {
			return e
		}
		if capacity > d.maximum {
			return qpackProblemOf("capacity_exceeded", errQPACKWire)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		d.table.capacity = capacity
		if !d.table.evict(0, nil) {
			return errQPACKWire
		}
		return nil
	default:
		index, e := readQPACKInt(r, first, 5)
		if e != nil {
			return e
		}
		d.mu.Lock()
		f, e = d.table.relative(index)
		d.mu.Unlock()
		if e != nil {
			return e
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.table.insert(f, nil) {
		return errQPACKWire
	}
	close(d.changed)
	d.changed = make(chan struct{})
	if d.feedbackMode == "on-insert" && d.send != nil {
		if err := d.send(appendQPACKInt(nil, 6, 0, d.table.inserted-d.reported)); err != nil {
			return err
		}
		d.reported = d.table.inserted
	}
	return nil
}
func (d *dynamicQPACKDecoder) readEncoder(r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		if err := d.instruction(br); err != nil {
			return err
		}
	}
}
func requiredInsertCount(encoded, total, maximum uint64) (uint64, error) {
	if encoded == 0 {
		return 0, nil
	}
	entries := maximum / 32
	full := 2 * entries
	if full == 0 || encoded > full || total > qpackIntegerLimit-entries {
		return 0, errQPACKWire
	}
	max := total + entries
	req := (max/full)*full + encoded - 1
	if req > max {
		if req <= full {
			return 0, errQPACKWire
		}
		req -= full
	}
	if req == 0 {
		return 0, errQPACKWire
	}
	return req, nil
}
func (d *dynamicQPACKDecoder) decode(ctx context.Context, stream uint64, block []byte, limit uint64) ([]qpack.HeaderField, error) {
	return d.decodeWithConnection(ctx, context.Background(), stream, block, limit)
}

// Request cancellation always applies. Connection termination only prevents
// waiting for missing inserts; it cannot invalidate a fully buffered section
// whose table dependencies are already available.
func (d *dynamicQPACKDecoder) decodeWithConnection(ctx, connection context.Context, stream uint64, block []byte, limit uint64) ([]qpack.HeaderField, error) {

	fail := func(err error) ([]qpack.HeaderField, error) {
		return nil, qpackFailure(ErrCodeQPACKDecompressionFailed, err)
	}
	r := bufio.NewReader(bytes.NewReader(block))
	first, err := r.ReadByte()
	if err != nil {
		return fail(err)
	}
	enc, err := readQPACKInt(r, first, 8)
	if err != nil {
		return fail(err)
	}
	b, err := r.ReadByte()
	if err != nil {
		return fail(err)
	}
	delta, err := readQPACKInt(r, b, 7)
	if err != nil {
		return fail(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	req, err := requiredInsertCount(enc, d.table.inserted, d.maximum)
	if err != nil {
		return fail(err)
	}
	var base uint64
	if b&0x80 != 0 {
		if delta >= req {
			return fail(errQPACKWire)
		}
		base = req - delta - 1
	} else {
		if delta > qpackIntegerLimit-req {
			return fail(errQPACKWire)
		}
		base = req + delta
	}
	if req > d.table.inserted {
		if !d.blocked[stream] && uint64(len(d.blocked)) >= d.blockedLimit {
			return fail(fmt.Errorf("QPACK blocked stream limit exceeded"))
		}
		d.blocked[stream] = true
		defer delete(d.blocked, stream)
		for req > d.table.inserted {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := connection.Err(); err != nil {
				return nil, err
			}
			changed := d.changed
			d.mu.Unlock()
			select {
			case <-changed:
			case <-ctx.Done():
			case <-connection.Done():
			}
			d.mu.Lock()
			// Recheck dependencies under the lock before interpreting a
			// simultaneous connection close. Explicit request cancel still
			// wins at the check below even when inserts became available.
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var fields []qpack.HeaderField
	var used, largest uint64
	reference := func(index uint64, post bool) (qpack.HeaderField, error) {
		var absolute uint64
		if post {
			if index > qpackIntegerLimit-base {
				return qpack.HeaderField{}, errQPACKWire
			}
			absolute = base + index
		} else {
			if index >= base {
				return qpack.HeaderField{}, qpackProblemOf("invalid_relative_index", errQPACKWire)
			}
			absolute = base - index - 1
		}
		if absolute >= req {
			return qpack.HeaderField{}, errQPACKWire
		}
		if absolute+1 > largest {
			largest = absolute + 1
		}
		return d.table.absolute(absolute)
	}
	for {
		b, err = r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
		var f qpack.HeaderField
		var index uint64
		switch {
		case b&0x80 != 0:
			index, err = readQPACKInt(r, b, 6)
			if err == nil {
				if b&0x40 != 0 {
					f, err = qpackStatic(index)
				} else {
					f, err = reference(index, false)
				}
			}
		case b&0xc0 == 0x40:
			index, err = readQPACKInt(r, b, 4)
			if err == nil {
				if b&0x10 != 0 {
					f, err = qpackStatic(index)
				} else {
					f, err = reference(index, false)
				}
			}
			if err == nil {
				var v byte
				v, err = r.ReadByte()
				if err == nil {
					f.Value, err = readQPACKString(r, v, 7, 0x80, limit)
				}
			}
		case b&0xe0 == 0x20:
			f.Name, err = readQPACKString(r, b, 3, 0x08, limit)
			if err == nil {
				var v byte
				v, err = r.ReadByte()
				if err == nil {
					f.Value, err = readQPACKString(r, v, 7, 0x80, limit)
				}
			}
		case b&0xf0 == 0x10:
			index, err = readQPACKInt(r, b, 4)
			if err == nil {
				f, err = reference(index, true)
			}
		default:
			index, err = readQPACKInt(r, b, 3)
			if err == nil {
				f, err = reference(index, true)
			}
			if err == nil {
				var v byte
				v, err = r.ReadByte()
				if err == nil {
					f.Value, err = readQPACKString(r, v, 7, 0x80, limit)
				}
			}
		}
		if err != nil {
			return fail(err)
		}
		size := entrySize(f)
		if size > limit-used {
			return fail(fmt.Errorf("QPACK field section exceeds limit"))
		}
		used += size
		fields = append(fields, f)
	}
	if largest != req {
		return fail(errQPACKWire)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req != 0 && d.send != nil {
		// A terminal connection has no surviving peer table to acknowledge.
		// Preserve every feedback failure while the connection is live.
		if connection.Err() == nil {
			if err = d.send(appendQPACKInt(nil, 7, 0x80, stream)); err != nil && connection.Err() == nil {
				return nil, err
			}
		}
		if req > d.reported {
			d.reported = req
		}
	}
	return fields, nil
}

// The encoder pins referenced entries until peer acknowledgment/cancellation and
// respects the peer blocked-stream budget. Insertion, warmup and base strategy
// are generic JSON-selected primitives, independent of browser identity.
type dynamicQPACKEncoder struct {
	budget           uint64
	drainingPercent  uint64
	warmup, sections uint64
	baseMode         string
	blockedLimit     uint64
	mu               sync.Mutex
	table            dynamicTable
	maximum, known   uint64
	initialized      bool
	// early is a table ALPS gave, known before the first section: the
	// warmup's sections are those written before the control stream's
	// SETTINGS are read, which ALPS's precede (configureEarly)
	early               bool
	mode, names, values string
	excluded            []string
	outstanding         map[uint64][]qpackOutstanding
	send                func([]byte) error
}
type qpackOutstanding struct {
	required uint64
	refs     map[uint64]bool
}

func newDynamicQPACKEncoder(mode, names, values string, excluded []string, send func([]byte) error) *dynamicQPACKEncoder {
	return &dynamicQPACKEncoder{mode: mode, names: names, values: values, excluded: excluded, outstanding: make(map[uint64][]qpackOutstanding), send: send}
}
func (e *dynamicQPACKEncoder) configure(max uint64, blocked ...uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(blocked) > 0 {
		e.blockedLimit = blocked[0]
	}
	e.maximum = max
	capacity := min(max, e.budget, qpackTableSafetyLimit)
	e.table.capacity = capacity
}

// configureEarly is configure with the settings a server gave in ALPS, which
// the first section is written with, as Chrome's first request is (bench
// h3alps, qpack-late: its control stream 300 ms late, Chrome's first request
// sets the capacity ALPS gave and inserts).
func (e *dynamicQPACKEncoder) configureEarly(max, blocked uint64) {
	e.configure(max, blocked)
	e.mu.Lock()
	e.early = true
	e.mu.Unlock()
}

func (e *dynamicQPACKEncoder) evictable(id uint64) bool {
	if id >= e.known {
		return false
	}
	for _, ss := range e.outstanding {
		for _, s := range ss {
			if s.refs[id] {
				return false
			}
		}
	}
	return true
}
func (e *dynamicQPACKEncoder) feedback(r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		first, err := br.ReadByte()
		if err != nil {
			return err
		}
		bits := uint8(6)
		if first&0x80 != 0 {
			bits = 7
		}
		n, err := readQPACKInt(br, first, bits)
		if err != nil {
			return err
		}
		e.mu.Lock()
		switch {
		case first&0x80 != 0:
			sections := e.outstanding[n]
			if len(sections) == 0 {
				err = errQPACKWire
			} else {
				if sections[0].required > e.known {
					e.known = sections[0].required
				}
				if len(sections) == 1 {
					delete(e.outstanding, n)
				} else {
					e.outstanding[n] = sections[1:]
				}
			}
		case first&0xc0 == 0x40:
			delete(e.outstanding, n)
		default:
			if n == 0 {
				err = qpackProblemOf("zero_increment", errQPACKWire)
			} else if n > e.table.inserted-e.known {
				err = errQPACKWire
			} else {
				e.known += n
			}
		}
		e.mu.Unlock()
		if err != nil {
			return err
		}
	}
}
func (e *dynamicQPACKEncoder) encode(stream uint64, fields []qpack.HeaderField) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	type representation struct {
		literal  []byte
		absolute uint64
		dynamic  bool
	}
	var reps []representation
	var instructions []byte
	refs := make(map[uint64]bool)
	var required uint64
	active := e.mode != "disabled" && e.table.capacity > 0 && (e.sections >= e.warmup || e.early)
	e.sections++
	if active && !e.initialized {
		instructions = appendQPACKInt(instructions, 5, 0x20, e.table.capacity)
		e.initialized = true
	}
	blockedStreams := uint64(0)
	alreadyBlocked := false
	for id, sections := range e.outstanding {
		for _, s := range sections {
			if s.required > e.known {
				blockedStreams++
				if id == stream {
					alreadyBlocked = true
				}
				break
			}
		}
	}
	mayBlock := alreadyBlocked || blockedStreams < e.blockedLimit
	// Stop adding references to the oldest selected capacity fraction. The
	// threshold is fixed for this section; newly inserted entries stay usable.
	draining := e.table.inserted
	space := e.table.capacity - e.table.size
	for _, entry := range e.table.entries {
		if space >= e.table.capacity*e.drainingPercent/100 {
			draining = entry.id
			break
		}
		space += entrySize(entry.field)
	}
	reference := func(id uint64) {
		reps = append(reps, representation{absolute: id, dynamic: true})
		refs[id] = true
		if id+1 > required {
			required = id + 1
		}
	}
	for _, f := range fields {
		var raw bytes.Buffer
		static := newPolicyQPACKEncoder(&raw)
		static.names = e.names
		static.values = e.values
		if err := static.WriteField(f); err != nil {
			return nil, err
		}
		literal := raw.Bytes()[2:]
		allowed := active && literal[0]&0x80 == 0
		for _, name := range e.excluded {
			if f.Name == name {
				allowed = false
				break
			}
		}
		found := false
		referenced := false
		if allowed {
			for i := len(e.table.entries) - 1; i >= 0; i-- {
				entry := e.table.entries[i]
				if entry.field == f {
					found = true
					if entry.id >= draining && (entry.id < e.known || mayBlock) {
						reference(entry.id)
						referenced = true
					} else if entry.id < draining && mayBlock && e.mode == "insert" {
						// Keep the source through the Duplicate instruction; do not
						// evict an unacknowledged or pinned prefix to make room.
						relative := e.table.inserted - entry.id - 1
						if e.table.insert(f, func(id uint64) bool { return id != entry.id && !refs[id] && e.evictable(id) }) {
							instructions = appendQPACKInt(instructions, 5, 0, relative)
							reference(e.table.inserted - 1)
							referenced = true
						}
					}
					// A draining exact match that cannot be duplicated may still
					// be inserted via a static name. That insertion can evict the
					// old value; unlike Duplicate it does not depend on its source.
					if !referenced && entry.id < draining && literal[0]&0xd0 == 0x50 {
						found = false
					}
					break
				}
			}
		}
		if allowed && !found && (mayBlock || e.mode == "reuse") {
			// Resolve the name reference before insertion, which may evict the source.
			var insertion []byte
			if literal[0]&0xd0 == 0x50 {
				index, _ := qpackPrefix(literal, 4)
				insertion = appendQPACKInt(nil, 6, 0xc0, index)
			} else {
				nameRef := false
				for i := len(e.table.entries) - 1; i >= 0; i-- {
					entry := e.table.entries[i]
					if entry.field.Name == f.Name {
						insertion = appendQPACKInt(nil, 6, 0x80, e.table.inserted-entry.id-1)
						nameRef = true
						break
					}
				}
				if !nameRef {
					insertion = appendQPACKString(nil, 5, 0x40, 0x20, f.Name, e.names)
				}
			}
			insertion = appendQPACKString(insertion, 7, 0, 0x80, f.Value, e.values)
			if e.table.insert(f, func(id uint64) bool { return !refs[id] && e.evictable(id) }) {
				instructions = append(instructions, insertion...)
				if e.mode == "insert" && mayBlock {
					reference(e.table.inserted - 1)
					referenced = true
				}
			}
		}
		if !referenced {
			reps = append(reps, representation{literal: append([]byte(nil), literal...)})
		}
	}
	if len(instructions) > 0 && e.send != nil {
		if err := e.send(instructions); err != nil {
			return nil, err
		}
	}
	base := required
	if e.baseMode == "insert-count" {
		base = e.table.inserted
	}
	var out []byte
	if required == 0 {
		out = []byte{0, 0}
	} else {
		out = appendQPACKInt(out, 8, 0, (required%(2*(e.maximum/32)))+1)
		out = appendQPACKInt(out, 7, 0, base-required)
		if len(e.outstanding) >= 8192 || len(e.outstanding[stream]) >= 8192 {
			return nil, fmt.Errorf("QPACK outstanding section safety limit")
		}
		e.outstanding[stream] = append(e.outstanding[stream], qpackOutstanding{required, refs})
	}
	for _, r := range reps {
		if r.dynamic {
			out = appendQPACKInt(out, 6, 0x80, base-r.absolute-1)
		} else {
			out = append(out, r.literal...)
		}
	}
	return out, nil
}
