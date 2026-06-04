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

## Skills practiced

The point of these projects is mainly to build comfort with Go and common network protocols.

So far, that includes:

diglet:

- Bitwise operations: working with DNS header flags where multiple flags are stored within a byte, or even crossing byte boundaries
- Processing raw bytes: encoding and decoding between useful Go structs and byte streams which can be sent over a network connection
- Implementing an RFC spec: reading the official protocol specifications and translating them to working code
- Binary protocol design: understanding why fixed-width fields, length-prefixed data, and network byte order (big-endian) exist and how they interact
- Go interfaces in practice: io.Reader, io.Writer, and how bytes.Buffer, bytes.Reader, and net.Conn all compose naturally because they satisfy the same interfaces
- Error wrapping: using %w to build error context as it bubbles up the call stack
- UDP networking: sending and receiving raw datagrams, and what constraints that puts on message size
- Package design: separating protocol logic from CLI concerns, deciding what to export, and designing a clean public API surface
