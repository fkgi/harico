package main

import (
	"bytes"
	"encoding/binary"
)

// CreateBAR IE
type CreateBAR struct {
	ID         byte `json:"ID"`
	BufPackets byte `json:"bufferingPacketsCount,omitempty"`
}

func (ie CreateBAR) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(85))
	buf := bytes.NewBuffer([]byte{0x00, 0x58, 0x00, 0x01, ie.ID})

	if ie.BufPackets != 0 {
		buf.Write([]byte{0x00, 0x8c, 0x00, 0x01, ie.BufPackets})
	}

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// UpdateBAR IE
type UpdateBAR struct {
	ID         byte `json:"ID"`
	BufPackets byte `json:"bufferingPacketsCount,omitempty"`
}

func (ie UpdateBAR) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(86))
	buf := bytes.NewBuffer([]byte{0x00, 0x58, 0x00, 0x01, ie.ID})

	if ie.BufPackets != 0 {
		buf.Write([]byte{0x00, 0x8c, 0x00, 0x01, ie.BufPackets})
	}

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// RemoveBAR IE
type RemoveBAR struct {
	ID byte `json:"ID"`
}

func (ie RemoveBAR) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(87))
	buf := bytes.NewBuffer([]byte{0x00, 0x58, 0x00, 0x01, ie.ID})

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}
