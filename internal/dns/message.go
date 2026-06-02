// Package dns parses and transmits DNS messages
package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
)

// Message represents the entire DNS message in its sections
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

// Header represents the header section of a standard DNS message
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question represents the question section of a standard DNS message
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord represents a DNS Resource Record - the data stored in each record
type ResourceRecord struct {
	Name       string
	Type       uint16
	Class      uint16
	TTL        int32
	DataLength uint16
	Data       string
}

const (
	flagQR = 1 << 15
	flagAA = 1 << 10
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagRA = 1 << 7
)

func newMessage(questions []Question, answers, authorities, additionals []ResourceRecord) (Message, error) {
	id, err := genRandomID()
	if err != nil {
		return Message{}, err
	}
	return Message{
		Header: Header{
			ID:      id,
			Flags:   uint16(flagRD),
			QDCount: uint16(len(questions)),
			ANCount: uint16(len(answers)),
			NSCount: uint16(len(authorities)),
			ARCount: uint16(len(additionals)),
		},
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}, nil
}

// decodeMessage decodes a DNS message from raw bytes to struct representations of each section
func decodeMessage(data []byte) (Message, error) {
	r := bytes.NewReader(data)
	header := decodeHeader(r)
	questions := make([]Question, header.QDCount)
	for range header.QDCount - 1 {
		question, err := decodeQuestion(r)
		if err != nil {
			return Message{}, err
		}
		questions = append(questions, question)
	}
	answers := make([]ResourceRecord, header.ANCount)
	for range header.ANCount - 1 {
		answer, err := decodeResourceRecord(r)
		if err != nil {
			return Message{}, err
		}
		answers = append(answers, answer)
	}
	authorities := make([]ResourceRecord, header.NSCount)
	for range header.NSCount - 1 {
		authority, err := decodeResourceRecord(r)
		if err != nil {
			return Message{}, err
		}
		authorities = append(authorities, authority)
	}
	additionals := make([]ResourceRecord, header.ARCount)
	for range header.ARCount - 1 {
		additional, err := decodeResourceRecord(r)
		if err != nil {
			return Message{}, err
		}
		additionals = append(additionals, additional)
	}
	return Message{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}, nil
}

func decodeHeader(r *bytes.Reader) Header {
	var h Header
	binary.Read(r, binary.BigEndian, &h)
	return h
}

func decodeQuestion(r *bytes.Reader) (Question, error) {
	var typ, class uint16
	name, err := decodeName(r)
	if err != nil {
		return Question{}, err
	}
	err = binary.Read(r, binary.BigEndian, &typ)
	if err != nil {
		return Question{}, err
	}
	err = binary.Read(r, binary.BigEndian, &class)
	if err != nil {
		return Question{}, err
	}
	return Question{
		Name:  name,
		Type:  typ,
		Class: class,
	}, err
}

func decodeResourceRecord(r *bytes.Reader) (ResourceRecord, error) {
	var typ, class, datalength uint16
	var ttl int32
	name, err := decodeName(r)
	if err != nil {
		return ResourceRecord{}, err
	}
	err = binary.Read(r, binary.BigEndian, &typ)
	if err != nil {
		return ResourceRecord{}, err
	}
	err = binary.Read(r, binary.BigEndian, &class)
	if err != nil {
		return ResourceRecord{}, err
	}
	err = binary.Read(r, binary.BigEndian, &ttl)
	if err != nil {
		return ResourceRecord{}, err
	}
	err = binary.Read(r, binary.BigEndian, &datalength)
	if err != nil {
		return ResourceRecord{}, err
	}
	data := make([]byte, datalength)
	_, err = r.Read(data)
	if err != nil {
		return ResourceRecord{}, err
	}
	return ResourceRecord{
		Name:       name,
		Type:       typ,
		Class:      class,
		TTL:        ttl,
		DataLength: datalength,
		Data:       string(data),
	}, nil
}

func decodeName(r *bytes.Reader) (string, error) {
	var labels []string
	for {
		length, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if length == 0 {
			break
		}
		buf := make([]byte, length)
		_, err = r.Read(buf)
		if err != nil {
			return "", err
		}
		labels = append(labels, string(buf))
	}
	return strings.Join(labels, "."), nil
}

// encodeMessage encodes a Message struct in a []byte slice for transmission
func encodeMessage(m Message) ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, m.Header)
	if err != nil {
		return nil, err
	}
	for _, q := range m.Questions {
		question, err := encodeQuestion(q)
		if err != nil {
			return nil, err
		}
		err = binary.Write(&buf, binary.BigEndian, question)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range m.Answers {
		record, err := encodeResourceRecord(r)
		if err != nil {
			return nil, err
		}
		err = binary.Write(&buf, binary.BigEndian, record)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range m.Authorities {
		record, err := encodeResourceRecord(r)
		if err != nil {
			return nil, err
		}
		err = binary.Write(&buf, binary.BigEndian, record)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range m.Additionals {
		record, err := encodeResourceRecord(r)
		if err != nil {
			return nil, err
		}
		err = binary.Write(&buf, binary.BigEndian, record)
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func encodeQuestion(q Question) ([]byte, error) {
	var buf bytes.Buffer
	nameBytes, err := encodeName(q.Name)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, nameBytes)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, q.Type)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, q.Class)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeResourceRecord(r ResourceRecord) ([]byte, error) {
	var buf bytes.Buffer
	nameBytes, err := encodeName(r.Name)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, nameBytes)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, r.Type)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, r.Class)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, r.TTL)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, r.DataLength)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, r.Data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeName(name string) ([]byte, error) {
	var buf bytes.Buffer
	labels := strings.Split(name, ".")
	for _, label := range labels {
		err := binary.Write(&buf, binary.BigEndian, len(label))
		if err != nil {
			return nil, err
		}
		err = binary.Write(&buf, binary.BigEndian, label)
		if err != nil {
			return nil, err
		}
	}
	err := binary.Write(&buf, binary.BigEndian, 0)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func genRandomID() (uint16, error) {
	var id uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &id)
	return id, err
}
