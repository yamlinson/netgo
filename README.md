# netgo

netgo is a collection of network utilities written in Go

## Build

Build a binary with `go build -o bin/ng main.go`

## Use

All utilities are contained under the `ng` binary and are called as subcommands

### diglet

diglet is a simple DNS client

It accepts exactly 1 argument, the name you want to resolve.

Optional flags can also be used to modify the request:

`-t type` sets the query type (default "A")
`-s server` sets the server to query (default "9.9.9.9")
`-p port` sets the server port to use (default 53)

Reverse lookups are not currently supported. Additional features may be added over time.
