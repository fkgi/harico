package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// CreatePDR IE
type CreatePDR struct {
	ID         uint16         `json:"ID"`
	Precedence uint32         `json:"precedence"`
	PDI        PDI            `json:"PDI"`
	Header     *HeaderRemoval `json:"header,omitempty"`
	FAR        uint32         `json:"FAR,omitempty"`
	URR        []uint32       `json:"URR,omitempty"`
	QER        []uint32       `json:"QER,omitempty"`
	// Activate Predefined Rules
	// Activation Time
	// Deactivation Time
	// MAR
	// Packet Replication and Detection Carry-On Information
	// IP Multicast Addressing Info
	// UE IP address Pool Identity
	// MPTCP Applicable Indication
}

func (ie CreatePDR) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(1))
	buf := bytes.NewBuffer([]byte{0x00, 0x38, 0x00, 0x02})
	binary.Write(buf, binary.BigEndian, ie.ID)

	buf.Write([]byte{0x00, 0x1d, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.Precedence)

	ie.PDI.encode(buf)

	if ie.Header != nil && ie.Header.Desctiption != 0 {
		ie.Header.encode(buf)
	}
	if ie.FAR != 0 {
		buf.Write([]byte{0x00, 0x6c, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, ie.FAR)
	}
	for _, urr := range ie.URR {
		buf.Write([]byte{0x00, 0x51, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, urr)
	}
	for _, qer := range ie.QER {
		buf.Write([]byte{0x00, 0x6d, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, qer)
	}

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// UpdatePDR IE
type UpdatePDR struct {
	ID         uint16         `json:"ID"`
	Header     *HeaderRemoval `json:"header,omitempty"`
	Precedence uint32         `json:"precedence,omitempty"`
	PDI        *PDI           `json:"PDI,omitempty"`
	FAR        uint32         `json:"FAR,omitempty"`
	URR        []uint32       `json:"URR,omitempty"`
	QER        []uint32       `json:"QER,omitempty"`
	// Activate Predefined Rules
	// Deactivate Predefined Rules
	// Activation Time
	// Deactivation Time
	// IP Multicast Addressing Info
}

func (ie UpdatePDR) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(9))
	buf := bytes.NewBuffer([]byte{0x00, 0x38, 0x00, 0x02})
	binary.Write(buf, binary.BigEndian, ie.ID)

	if ie.Header != nil && ie.Header.Desctiption != 0 {
		ie.Header.encode(buf)
	}
	if ie.Precedence != 0 {
		buf.Write([]byte{0x00, 0x1d, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, ie.Precedence)
	}
	if ie.PDI != nil {
		ie.PDI.encode(buf)
	}
	if ie.FAR != 0 {
		buf.Write([]byte{0x00, 0x6c, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, ie.FAR)
	}
	for _, urr := range ie.URR {
		buf.Write([]byte{0x00, 0x51, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, urr)
	}
	for _, qer := range ie.QER {
		buf.Write([]byte{0x00, 0x6d, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, qer)
	}

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// RemovePDR IE
type RemovePDR struct {
	ID uint16 `json:"ID"`
}

func (ie RemovePDR) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(15))
	buf := bytes.NewBuffer([]byte{0x00, 0x38, 0x00, 0x02})
	binary.Write(buf, binary.BigEndian, ie.ID)

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// CreatedPDR IE
type CreatedPDR struct {
	ID    uint16 `json:"ID"`
	FTEID *FTEID `json:"FTEID,omitempty"`
	// Local F-TEID for Redundant Transmission
	UEIP *UEIP `json:"UE_IP,omitempty"`
}

func (ie *CreatedPDR) decode(b []byte) (e error) {
	buf := bytes.NewReader(b)
	var t, n uint16
	var l int

	for buf.Len() > 0 {
		if e = binary.Read(buf, binary.BigEndian, &t); e != nil {
			break
		}
		if e = binary.Read(buf, binary.BigEndian, &n); e != nil {
			break
		}
		b = make([]byte, int(n))
		if l, e = buf.Read(b); e != nil {
			break
		}
		if l != len(b) {
			e = io.ErrUnexpectedEOF
			break
		}

		switch t {
		case 56:
			if len(b) < 2 {
				e = fmt.Errorf("invalid data")
			} else {
				ie.ID = uint16(b[0])
				ie.ID = (ie.ID << 8) | uint16(b[1])
			}
		case 21:
			ie.FTEID = &FTEID{}
			e = ie.FTEID.decode(b)
		case 93:
			ie.UEIP = &UEIP{}
			e = ie.UEIP.decode(b)
		}
		if e != nil {
			break
		}
	}

	return
}

// UpdatedPDR IE
type UpdatedPDR struct {
	ID uint16 `json:"ID"`
	// Local F-TEID for Redundant Transmission
}

func (ie *UpdatedPDR) decode(b []byte) (e error) {
	buf := bytes.NewReader(b)
	var t, n uint16
	var l int

	for buf.Len() > 0 {
		if e = binary.Read(buf, binary.BigEndian, &t); e != nil {
			break
		}
		if e = binary.Read(buf, binary.BigEndian, &n); e != nil {
			break
		}
		b = make([]byte, int(n))
		if l, e = buf.Read(b); e != nil {
			break
		}
		if l != len(b) {
			e = io.ErrUnexpectedEOF
			break
		}

		switch t {
		case 56:
			if len(b) < 2 {
				e = fmt.Errorf("invalid data")
			} else {
				ie.ID = uint16(b[0])
				ie.ID = (ie.ID << 8) | uint16(b[1])
			}
		}
		if e != nil {
			break
		}
	}

	return
}

// PDI IE
type PDI struct {
	Interface Interface `json:"interface"`
	FTEID     *FTEID    `json:"FTEID,omitempty"`
	Instance  string    `json:"instance,omitempty"`
	//Redundant Transmission Parameters
	UEIP *UEIP `json:"UE_IP,omitempty"`
	//Traffic Endpoint ID
	//SDF Filter
	//Application ID
	//Ethernet PDU Session Information
	//Ethernet Packet Filter
	QFI byte `json:"QFI,omitempty"`
	//Framed-Route
	//Framed-Routing
	//Framed-IPv6-Route
	//Source Interface Type
	//IP Multicast Addressing Info
}

func (p PDI) encode(b *bytes.Buffer) {
	binary.Write(b, binary.BigEndian, uint16(2))
	buf := &bytes.Buffer{}

	p.Interface.encodeRx(buf)
	if p.FTEID != nil {
		p.FTEID.encode(buf)
	}
	if len(p.Instance) != 0 {
		buf.Write([]byte{0x00, 0x16,
			byte(len(p.Instance) >> 8), byte(len(p.Instance))})
		buf.WriteString(p.Instance)
	}
	if p.UEIP != nil {
		p.UEIP.encode(buf)
	}
	if p.QFI != 0 {
		buf.Write([]byte{0x00, 0x7c, 0x00, 0x01, p.QFI})
	}

	binary.Write(b, binary.BigEndian, uint16(buf.Len()))
	buf.WriteTo(b)
}

// HeaderRemoval IE
type HeaderRemoval struct {
	Desctiption int  `json:"description"`
	Extension   byte `json:"extensionHeader,omitempty"`
}

// MarshalJSON returns JSON of ie
func (ie HeaderRemoval) MarshalJSON() ([]byte, error) {
	js := struct {
		Desctiption      string `json:"description"`
		SessionContainer bool   `json:"sessionContainer,omitempty"`
	}{}

	switch ie.Desctiption {
	case 1:
		js.Desctiption = "GTP-U/UDP/IPv4"
	case 2:
		js.Desctiption = "GTP-U/UDP/IPv6"
	case 3:
		js.Desctiption = "UDP/IPv4"
	case 4:
		js.Desctiption = "UDP/IPv6"
	case 5:
		js.Desctiption = "IPv4"
	case 6:
		js.Desctiption = "IPv6"
	case 7:
		js.Desctiption = "GTP-U/UDP/IP"
	case 8:
		js.Desctiption = "VLAN_S-TAG"
	case 9:
		js.Desctiption = "S-TAG_C-TAG"
	default:
		return nil, fmt.Errorf("invalid Outer Header Removal Description %d", ie.Desctiption)
	}
	if ie.Extension == 0x01 {
		js.SessionContainer = true
	}

	return json.Marshal(js)
}

// UnmarshalJSON sets value of data to *ie.
func (ie *HeaderRemoval) UnmarshalJSON(data []byte) error {
	js := struct {
		Desctiption      string `json:"description"`
		SessionContainer bool   `json:"sessionContainer,omitempty"`
	}{}
	if e := json.Unmarshal(data, &js); e != nil {
		return e
	}

	switch js.Desctiption {
	case "GTP-U/UDP/IPv4":
		ie.Desctiption = 1
	case "GTP-U/UDP/IPv6":
		ie.Desctiption = 2
	case "UDP/IPv4":
		ie.Desctiption = 3
	case "UDP/IPv6":
		ie.Desctiption = 4
	case "IPv4":
		ie.Desctiption = 5
	case "IPv6":
		ie.Desctiption = 6
	case "GTP-U/UDP/IP":
		ie.Desctiption = 7
	case "VLAN_S-TAG":
		ie.Desctiption = 8
	case "S-TAG_C-TAG":
		ie.Desctiption = 9
	default:
		return fmt.Errorf("invalid Outer Header Removal Description %s", js.Desctiption)
	}
	if js.SessionContainer {
		ie.Extension = 0x01
	}
	return nil
}

func (ie HeaderRemoval) encode(b *bytes.Buffer) {
	data := []byte{0x00, 0x5f, 0x00, 0x00, 0x00}
	if ie.Extension != 0 {
		data[3] = 0x02
	} else {
		data[3] = 0x01
	}
	switch ie.Desctiption {
	case 1:
		data[4] = 0
	case 2:
		data[4] = 1
	case 3:
		data[4] = 2
	case 4:
		data[4] = 3
	case 5:
		data[4] = 4
	case 6:
		data[4] = 5
	case 7:
		data[4] = 6
	case 8:
		data[4] = 7
	case 9:
		data[4] = 8
	}
	b.Write(data)
	if ie.Extension != 0 {
		b.WriteByte(ie.Extension)
	}
}
