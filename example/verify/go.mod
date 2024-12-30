module main

go 1.20

require github.com/google/go-tpm-tools v0.4.0 // indirect

require github.com/salrashid123/gcp-vtpm-ek-ak/parser v0.0.0

require (
	github.com/google/go-sev-guest v0.6.1 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace github.com/salrashid123/gcp-vtpm-ek-ak/parser => ../../parser
