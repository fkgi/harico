package main

import "bytes"

// CreateBAR IE
type CreateBAR struct {
	ID                             byte `json:"ID"`
	SuggestedBufferingPacketsCount byte `json:"suggestedBufferingPacketsCount,omitempty"`
}

func (ie CreateBAR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x55, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x58, 0x00, 0x01, ie.ID})

	if ie.SuggestedBufferingPacketsCount != 0 {
		buf.Write([]byte{0x00, 0x8c, 0x00, 0x01, ie.SuggestedBufferingPacketsCount})
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// RemoveBAR IE
type RemoveBAR struct {
	ID byte `json:"ID"`
}

func (ie RemoveBAR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x57, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x58, 0x00, 0x01, ie.ID})

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// UpdateBAR IE
type UpdateBAR struct {
	ID                             byte `json:"ID"`
	SuggestedBufferingPacketsCount byte `json:"suggestedBufferingPacketsCount,omitempty"`
}

func (ie UpdateBAR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x56, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x58, 0x00, 0x01, ie.ID})

	if ie.SuggestedBufferingPacketsCount != 0 {
		buf.Write([]byte{0x00, 0x8c, 0x00, 0x01, ie.SuggestedBufferingPacketsCount})
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}
