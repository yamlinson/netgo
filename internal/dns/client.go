// Package dns parses and transmits DNS messages
package dns

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

const (
	classIN      = uint16(1)
	connDeadline = 30 * time.Second
)

// ErrIDMismatch is returned when the ID of a server response does not match the ID of the client request
var ErrIDMismatch = errors.New("response ID does not match request ID")

// Query sends a request to the given server and returns its response as a Message
func Query(name string, qtype uint16, server string) (Message, error) {
	slog.Debug("preparing request", "name", name, "type", qtype, "server", server)
	reqMessage, err := newMessage(
		[]Question{
			{
				Name:  name,
				Type:  qtype,
				Class: classIN,
			},
		},
		nil, nil, nil,
	)
	if err != nil {
		return Message{}, fmt.Errorf("preparing request: %w", err)
	}
	slog.Debug("encoding message", "message", reqMessage)
	req, err := encodeMessage(reqMessage)
	if err != nil {
		return Message{}, fmt.Errorf("preparing request: %w", err)
	}

	slog.Debug("connecting to server", "server", server)
	conn, err := net.Dial("udp", server)
	if err != nil {
		return Message{}, fmt.Errorf("sending request: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(connDeadline)); err != nil {
		return Message{}, fmt.Errorf("sending request: %w", err)
	}
	slog.Debug("connection deadline set", "duration", connDeadline)

	slog.Debug("sending request", "req", req)
	_, err = conn.Write(req)
	if err != nil {
		return Message{}, fmt.Errorf("sending request: %w", err)
	}

	buf := make([]byte, 512)

	n, err := conn.Read(buf)
	if err != nil {
		return Message{}, fmt.Errorf("reading response: %w", err)
	}

	slog.Debug("received response", "res", buf[:n])
	resMessage, err := decodeMessage(buf[:n])
	if err != nil {
		return Message{}, fmt.Errorf("reading response: %w", err)
	}
	slog.Debug("decoded response", "response", resMessage)

	if reqMessage.Header.ID != resMessage.Header.ID {
		return Message{}, ErrIDMismatch
	}

	return resMessage, nil
}
