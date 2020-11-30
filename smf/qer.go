package main

import (
	"bytes"
	"encoding/binary"
)

// CreateQER IE
type CreateQER struct {
	ID          uint32     `json:"ID"`
	Correlation uint32     `json:"correlationID,omitempty"`
	GateStatus  GateStatus `json:"gateStatus"`
	MBR         *bitrate   `json:"MBR,omitempty"`
	GBR         *bitrate   `json:"GBR,omitempty"`
	// Packet Rate Status
	QFI byte `json:"QFI,omitempty"`
	RQI bool `json:"RQI,omitempty"`
	PPI byte `json:"PPI,omitempty"`
	// Averaging Window
	// QER Control Indications
}

func (ie CreateQER) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(7))
	buf := bytes.NewBuffer([]byte{0x00, 0x6d, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	ie.GateStatus.encode(buf)
	if ie.Correlation != 0 {
		buf.Write([]byte{0x00, 0x1c, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, ie.Correlation)
	}
	if ie.MBR != nil {
		buf.Write([]byte{0x00, 0x1a, 0x00, 0x0a})
		buf.Write(ie.MBR.ulBytes())
		buf.Write(ie.MBR.dlBytes())
	}
	if ie.GBR != nil {
		buf.Write([]byte{0x00, 0x1b, 0x00, 0x0a})
		buf.Write(ie.GBR.ulBytes())
		buf.Write(ie.GBR.dlBytes())
	}
	if ie.QFI != 0 {
		buf.Write([]byte{0x00, 0x7c, 0x00, 0x01, ie.QFI})
	}
	if ie.RQI {
		buf.Write([]byte{0x00, 0x7b, 0x00, 0x01, 0x01})
	}
	if ie.PPI != 0 {
		buf.Write([]byte{0x00, 0x9e, 0x00, 0x01, ie.PPI})
	}

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// UpdateQER IE
type UpdateQER struct {
	ID          uint32      `json:"ID"`
	Correlation uint32      `json:"correlationID,omitempty"`
	GateStatus  *GateStatus `json:"gateStatus,omitempty"`
	MBR         *bitrate    `json:"MBR,omitempty"`
	GBR         *bitrate    `json:"GBR,omitempty"`
	QFI         byte        `json:"QFI,omitempty"`
	RQI         bool        `json:"RQI,omitempty"`
	PPI         byte        `json:"PPI,omitempty"`
	// Averaging Window
	// QER Control Indications
}

func (ie UpdateQER) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(14))
	buf := bytes.NewBuffer([]byte{0x00, 0x6d, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	if ie.Correlation != 0 {
		buf.Write([]byte{0x00, 0x1c, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, ie.Correlation)
	}
	if ie.GateStatus != nil {
		ie.GateStatus.encode(buf)
	}
	if ie.MBR != nil {
		buf.Write([]byte{0x00, 0x1a, 0x00, 0x08})
		binary.Write(buf, binary.BigEndian, ie.MBR.UL)
		binary.Write(buf, binary.BigEndian, ie.MBR.DL)
	}
	if ie.GBR != nil {
		buf.Write([]byte{0x00, 0x1b, 0x00, 0x08})
		binary.Write(buf, binary.BigEndian, ie.GBR.UL)
		binary.Write(buf, binary.BigEndian, ie.GBR.DL)
	}
	if ie.QFI != 0 {
		buf.Write([]byte{0x00, 0x7c, 0x00, 0x01, ie.QFI})
	}
	if ie.RQI {
		buf.Write([]byte{0x00, 0x7b, 0x00, 0x01, 0x01})
	}
	if ie.PPI != 0 {
		buf.Write([]byte{0x00, 0x9e, 0x00, 0x01, ie.PPI})
	}

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// RemoveQER IE
type RemoveQER struct {
	ID uint32 `json:"ID"`
}

func (ie RemoveQER) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(18))
	buf := bytes.NewBuffer([]byte{0x00, 0x6d, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

type bitrate struct {
	UL uint64 `json:"ul"`
	DL uint64 `json:"dl"`
}

func (ie bitrate) ulBytes() []byte {
	return []byte{
		byte(ie.UL >> 32),
		byte(ie.UL >> 24),
		byte(ie.UL >> 16),
		byte(ie.UL >> 8),
		byte(ie.UL),
	}
}

func (ie bitrate) dlBytes() []byte {
	return []byte{
		byte(ie.DL >> 32),
		byte(ie.DL >> 24),
		byte(ie.DL >> 16),
		byte(ie.DL >> 8),
		byte(ie.DL),
	}
}

// GateStatus IE
type GateStatus struct {
	UL bool `json:"ul"`
	DL bool `json:"dl"`
}

func (ie GateStatus) encode(b *bytes.Buffer) {
	var g byte = 0x00
	if !ie.UL {
		g = g | 0x04
	}
	if !ie.DL {
		g = g | 0x01
	}
	b.Write([]byte{0x00, 0x19, 0x00, 0x01, g})
}
