package main

import (
	"bytes"
	"encoding/binary"
	"net"
)

// CreateFAR IE
type CreateFAR struct {
	ID         uint32               `json:"ID"`
	Action     Action               `json:"action"`
	Forwarding *ForwardingParameter `json:"forwardingParam,omitempty"`
	BAR        byte                 `json:"BAR,omitempty"`
	// Redundant Transmission Parameters
}

func (ie CreateFAR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x03, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x6c, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	ie.Action.encode(buf)

	if ie.Forwarding != nil {
		ie.Forwarding.encode(buf)
	}

	if ie.BAR != 0 {
		buf.Write([]byte{0x00, 0x58, 0x00, 0x01, ie.BAR})
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// RemoveFAR IE
type RemoveFAR struct {
	ID uint32 `json:"ID"`
}

func (ie RemoveFAR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x10, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x6c, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// UpdateFAR IE
type UpdateFAR struct {
	ID         uint32                     `json:"ID"`
	Action     *Action                    `json:"action,omitempty"`
	Forwarding *UpdateForwardingParameter `json:"forwardingParam,omitempty"`
	// Redundant Transmission Parameters
	BAR byte `json:"BAR,omitempty"`
}

func (ie UpdateFAR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x0a, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x6c, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	if ie.Action != nil {
		ie.Action.encode(buf)
	}
	if ie.Forwarding != nil {
		ie.Forwarding.encode(buf)
	}
	if ie.BAR != 0 {
		buf.Write([]byte{0x00, 0x58, 0x00, 0x01, ie.BAR})
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// Action IE
type Action struct {
	DROP bool `json:"DROP,omitempty"`
	FORW bool `json:"FORW,omitempty"`
	BUFF bool `json:"BUFF,omitempty"`
	IPMA bool `json:"IPMA,omitempty"`
	IPMD bool `json:"IPMD,omitempty"`
	NOCP bool `json:"NOCP,omitempty"`
	BDPN bool `json:"BDPN,omitempty"`
	DDPN bool `json:"DDPN,omitempty"`
	DUPL bool `json:"DUPL,omitempty"`
	DFRT bool `json:"DFRT,omitempty"`
	EDRT bool `json:"EDRT,omitempty"`
}

func (ie Action) encode(b *bytes.Buffer) {
	a := [2]byte{}
	if ie.DROP {
		a[0] |= 0x01
	}
	if ie.FORW {
		a[0] |= 0x02
	}
	if ie.BUFF {
		a[0] |= 0x04
	}
	if ie.IPMA {
		a[0] |= 0x20
	}
	if ie.IPMD {
		a[0] |= 0x40
	}
	if ie.NOCP {
		a[0] |= 0x08
	}
	if ie.BDPN {
		a[1] |= 0x02
	}
	if ie.DDPN {
		a[1] |= 0x04
	}
	if ie.DUPL {
		a[0] |= 0x10
	}
	if ie.DFRT {
		a[0] |= 0x80
	}
	if ie.EDRT {
		a[1] |= 0x01
	}
	b.Write([]byte{0x00, 0x2c, 0x00})
	if a[1] == 0x00 {
		b.Write([]byte{0x01, a[0]})
	} else {
		b.Write([]byte{0x02, a[0], a[1]})
	}
}

// ForwardingParameter IE
type ForwardingParameter struct {
	Interface Interface `json:"interface"`
	Instance  string    `json:"instance,omitempty"`
	// Redirect Information
	Header           *HeaderCreation `json:"header,omitempty"`
	TransportMarking byte            `json:"transportMarking,omitempty"`
	// Forwarding Policy
	// Header Enrichment
	// Linked Traffic Endpoint ID
	// Proxying
	// Destination Interface Type
}

func (ie ForwardingParameter) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x04, 0x00, 0x00})

	ie.Interface.encodeTx(buf)

	if len(ie.Instance) != 0 {
		buf.Write([]byte{0x00, 0x16,
			byte(len(ie.Instance) >> 8), byte(len(ie.Instance))})
		buf.WriteString(ie.Instance)
	}
	if ie.Header != nil {
		ie.Header.encode(buf)
	}
	if ie.TransportMarking != 0 {
		b.Write([]byte{0x00, 0x1e, 0x00, 0x02,
			ie.TransportMarking, 0xfc})
	}
	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// UpdateForwardingParameter IE
type UpdateForwardingParameter struct {
	Interface Interface `json:"interface,omitempty"`
	Instance  string    `json:"instance,omitempty"`
	// Redirect Information
	Header           *HeaderCreation `json:"header,omitempty"`
	TransportMarking byte            `json:"transportMarking,omitempty"`
	// Forwarding Policy
	// Header Enrichment
	// PFCPSMReq-Flags
	// Linked Traffic Endpoint ID
	// Destination Interface Type
}

func (ie UpdateForwardingParameter) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x0b, 0x00, 0x00})

	if ie.Interface != 0 {
		ie.Interface.encodeTx(buf)
	}
	if len(ie.Instance) != 0 {
		buf.Write([]byte{0x00, 0x16,
			byte(len(ie.Instance) >> 8), byte(len(ie.Instance))})
		buf.WriteString(ie.Instance)
	}
	if ie.Header != nil {
		ie.Header.encode(buf)
	}
	if ie.TransportMarking != 0 {
		b.Write([]byte{0x00, 0x1e, 0x00, 0x02,
			ie.TransportMarking, 0xfc})
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// HeaderCreation indicate Outer Header Creation IE
type HeaderCreation struct {
	ID   uint32 `json:"ID,omitempty"`
	IPv4 net.IP `json:"IPv4,omitempty"`
	IPv6 net.IP `json:"IPv6,omitempty"`
	Port uint16 `json:"port,omitempty"`
	CTag uint16 `json:"ctag,omitempty"`
	STag uint16 `json:"stag,omitempty"`
	N19  bool   `json:"n19,omitempty"`
	N6   bool   `json:"n6,omitempty"`
}

func (ie HeaderCreation) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x54, 0x00, 0x00, 0x00, 0x00})

	var desc byte = 0x00
	if ie.ID != 0 {
		binary.Write(buf, binary.BigEndian, ie.ID)
		if ie.IPv4 != nil {
			desc = desc | 0x01
			buf.Write(ie.IPv4.To4())
		}
		if ie.IPv6 != nil {
			desc = desc | 0x02
			buf.Write(ie.IPv6.To16())
		}
	} else if ie.Port != 0 {
		if ie.IPv4 != nil {
			desc = desc | 0x04
			buf.Write(ie.IPv4.To4())
		}
		if ie.IPv6 != nil {
			desc = desc | 0x08
			buf.Write(ie.IPv6.To16())
		}
		binary.Write(buf, binary.BigEndian, ie.Port)
	} else if ie.IPv4 != nil || ie.IPv6 != nil {
		if ie.IPv4 != nil {
			desc = desc | 0x10
			buf.Write(ie.IPv4.To4())
		}
		if ie.IPv6 != nil {
			desc = desc | 0x20
			buf.Write(ie.IPv6.To16())
		}
	} else if ie.CTag != 0 {
		desc = desc | 0x40
		binary.Write(buf, binary.BigEndian, ie.CTag)
	} else if ie.STag != 0 {
		desc = desc | 0x80
		binary.Write(buf, binary.BigEndian, ie.STag)
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	data[4] = desc
	if ie.N19 {
		data[5] = data[5] | 0x01
	}
	if ie.N6 {
		data[5] = data[5] | 0x02
	}
	b.Write(data)
}
