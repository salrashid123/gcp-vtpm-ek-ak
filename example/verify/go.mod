module main

go 1.20

require github.com/google/go-tpm-tools v0.4.0 // indirect

require github.com/salrashid123/gcp-tpm/parser v0.0.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/go-sev-guest v0.6.1 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/salrashid123/golang-jwt-tpm v1.5.0 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/sys v0.8.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace github.com/salrashid123/gcp-tpm/parser => ../../parser
