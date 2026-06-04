// Package dns parses and transmits DNS messages
package dns

import (
	"bytes"
	"reflect"
	"slices"
	"testing"
)

func TestDecodeName(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		offset   int
		expected string
	}{
		{
			name:     "single label",
			input:    []byte{0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x00},
			expected: "google",
		},
		{
			name:     "two labels",
			input:    []byte{0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
			expected: "google.com",
		},
		{
			name:     "no labels",
			input:    []byte{0x00},
			expected: "",
		},
		{
			name: "simple compression pointer",
			input: []byte{
				// offset 0: "com" stored here for the pointer to reference
				0x03, 'c', 'o', 'm', 0x00,
				// offset 5: "google" + pointer to offset 0
				0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0xC0, 0x00,
			},
			offset:   5,
			expected: "google.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input[tt.offset:])
			got, err := decodeName(r, tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestEncodeName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "single label",
			input:    "google",
			expected: []byte{0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x00},
		},
		{
			name:     "two labels",
			input:    "google.com",
			expected: []byte{0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
		},
		{
			name:     "no labels",
			input:    "",
			expected: []byte{0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeName(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, tt.expected) {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestEncodeDecode(t *testing.T) {
	t.Run("encode then decode request", func(t *testing.T) {
		original := Message{
			Header: Header{
				ID:      42,
				Flags:   32768,
				QDCount: 1,
				ANCount: 0,
				NSCount: 0,
				ARCount: 0,
			},
			Questions: []Question{
				{
					Name:  "google.com",
					Type:  1,
					Class: 1,
				},
			},
			Answers:     []ResourceRecord{},
			Authorities: []ResourceRecord{},
			Additionals: []ResourceRecord{},
		}
		encoded, _ := encodeMessage(original)
		decoded, _ := decodeMessage(encoded)
		if !reflect.DeepEqual(original, decoded) {
			t.Errorf("got %+v, want %+v", decoded, original)
		}
	})
}
