package http3

import (
	"errors"
	"github.com/igor-lemon/utls/behavior"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Classification is a parser fact. Wire diagnostic text is selected from the
// immutable profile, never from a browser name or a loose string match.
type qpackProblem struct {
	kind string
	err  error
}

func (e *qpackProblem) Error() string             { return e.err.Error() }
func (e *qpackProblem) Unwrap() error             { return e.err }
func qpackProblemOf(kind string, err error) error { return &qpackProblem{kind, err} }
func qpackProblemKey(err error, fallback string) string {
	var problem *qpackProblem
	if errors.As(err, &problem) {
		return "h3.qpack.error_" + problem.kind + "_reason"
	}
	return "h3.qpack.error_" + fallback + "_reason"
}
func qpackReason(p behavior.Policy, key string, err error, stream uint64) string {
	detail := ""
	if err != nil {
		detail = strings.ToValidUTF8(err.Error(), "�")
	}
	value := strings.NewReplacer("{stream_id}", strconv.FormatUint(stream, 10), "{detail}", detail).Replace(p.Text(key))
	// A peer/IO error or repeated template cannot create an unbounded close frame.
	const diagnosticSafetyLimit = 1024
	if len(value) > diagnosticSafetyLimit {
		value = value[:diagnosticSafetyLimit]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}
