# quic-go-utls for tls-forge

A fork of [bogdanfinn/quic-go-utls](https://github.com/bogdanfinn/quic-go-utls)
v1.0.10-utls (`4e6a46505b5f54c5bff5db72b600795648364e09`), on the branch
`tls-forge`, for [tls-forge](https://github.com/Sec-CH-Lemon/tls-forge).

- The module is `github.com/igor-lemon/quic-go-utls`, and it imports fhttp
  and utls as `github.com/igor-lemon/fhttp` and `github.com/igor-lemon/utls`,
  the forks tls-forge patches: tls-client hands their types to this module's
  http3, so both have to name the same ones. On another base:

      grep -rlE 'github\.com/bogdanfinn/(fhttp|utls|quic-go-utls)' --include='*.go' --include=go.mod . |
        xargs perl -pi -e 's#github\.com/bogdanfinn/(fhttp|utls|quic-go-utls)\b#github.com/igor-lemon/$1#g'

  then `git diff --name-only -- '*.go' | xargs gofmt -w`, which puts the
  renamed imports back in order, `go mod edit
  -require=github.com/igor-lemon/fhttp@<version>
  -require=github.com/igor-lemon/utls@<version>` and `go mod tidy`.
- At the base, `go vet` refuses `integrationtests/self/self_go125_test.go`
  (utls's ConnectionState has no CurveID), upstream as here.
