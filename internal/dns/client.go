// Package dns parses and transmits DNS messages
package dns

import (
	"errors"
	"net"
	"time"
)

const (
	classIN = uint16(1)
)

// ErrIDMismatch is returned when the ID of a server response does not match the ID of the client request
var ErrIDMismatch = errors.New("response ID does not match request ID")

// Query sends a request to the given server and returns its response as a Message
func Query(name string, qtype uint16, server string) (Message, error) {
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
		return Message{}, err
	}
	req, err := encodeMessage(reqMessage)
	if err != nil {
		return Message{}, err
	}

	conn, err := net.Dial("udp", server)
	if err != nil {
		return Message{}, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return Message{}, err
	}

	_, err = conn.Write(req)
	if err != nil {
		return Message{}, err
	}

	buf := make([]byte, 512)

	n, err := conn.Read(buf)
	if err != nil {
		return Message{}, err
	}

	resMessage, err := decodeMessage(buf[:n])
	if err != nil {
		return Message{}, err
	}

	if reqMessage.Header.ID != resMessage.Header.ID {
		return Message{}, ErrIDMismatch
	}

	return resMessage, nil
}
