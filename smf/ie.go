package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Interface IE
type Interface int

// MarshalText returns text of ie
func (ie Interface) MarshalText() ([]byte, error) {
	switch ie {
	case 1:
		return []byte("Access"), nil
	case 2:
		return []byte("Core"), nil
	case 3:
		return []byte("N6-LAN"), nil
	case 4:
		return []byte("CP-function"), nil
	case 5:
		return []byte("LI-function"), nil
	case 6:
		return []byte("VN-Internal"), nil
	}
	return nil, fmt.Errorf("invalid Interface: %d", ie)
}

// UnmarshalText sets value of data to *ie.
func (ie *Interface) UnmarshalText(data []byte) error {
	switch string(data) {
	case "Access":
		*ie = 1
	case "Core":
		*ie = 2
	case "N6-LAN":
		*ie = 3
	case "CP-function":
		*ie = 4
	case "LI-function":
		*ie = 5
	case "VN-Internal":
		*ie = 6
	default:
		return fmt.Errorf("invalid Interface: %s", string(data))
	}
	return nil
}

func (ie Interface) encodeRx(b *bytes.Buffer) {
	data := []byte{0x00, 0x14, 0x00, 0x01, 0x00}
	switch ie {
	case 1:
		data[4] = 0x00
	case 2:
		data[4] = 0x01
	case 3:
		data[4] = 0x02
	case 4:
		data[4] = 0x03
	case 6:
		data[4] = 0x04
	default:
		return
	}
	b.Write(data)
}

func (ie Interface) encodeTx(b *bytes.Buffer) {
	data := []byte{0x00, 0x2a, 0x00, 0x01, 0x00}
	switch ie {
	case 1:
		data[4] = 0x00
	case 2:
		data[4] = 0x01
	case 3:
		data[4] = 0x02
	case 4:
		data[4] = 0x03
	case 5:
		data[4] = 0x04
	case 6:
		data[4] = 0x05
	default:
		return
	}
	b.Write(data)
}

// FTEID indicate F-TEID IE
type FTEID struct {
	ID       uint32 `json:"ID,omitempty"`
	ChooseID byte   `json:"choosID,omitempty"`
	IPv4     net.IP `json:"IPv4,omitempty"`
	IPv6     net.IP `json:"IPv6,omitempty"`
}

func (ie FTEID) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x15, 0x00, 0x00, 0x00})

	var flag byte = 0x00
	if ie.ID == 0 {
		flag = flag | 0x04
	} else {
		binary.Write(buf, binary.BigEndian, ie.ID)
	}
	if ie.IPv4 != nil {
		flag = flag | 0x01
		if ie.ID != 0 {
			buf.Write(ie.IPv4.To4())
		}
	}
	if ie.IPv6 != nil {
		flag = flag | 0x02
		if ie.ID != 0 {
			buf.Write(ie.IPv6.To16())
		}
	}
	if ie.ChooseID != 0 {
		flag = flag | 0x08
		buf.WriteByte(ie.ChooseID)
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	data[4] = flag
	b.Write(data)
}

func (ie *FTEID) decode(b []byte) (e error) {
	buf := bytes.NewReader(b)
	var flag byte

	if flag, e = buf.ReadByte(); e != nil {
		return
	}
	if flag&0x0c != 0x00 {
		e = fmt.Errorf("invalid data")
		return
	}
	if e = binary.Read(buf, binary.BigEndian, &ie.ID); e != nil {
		return
	}
	if flag&0x01 == 0x01 {
		ie.IPv4 = []byte{0, 0, 0, 0}
		_, e = buf.Read(ie.IPv4)
		if e != nil {
			return
		}
	}
	if flag&0x02 == 0x02 {
		ie.IPv6 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		_, e = buf.Read(ie.IPv6)
		if e != nil {
			return
		}
	}
	return
}

// UEIP indicate UE IP address IE
type UEIP struct {
	Dest bool   `json:"dest,omitempty"`
	IPv4 net.IP `json:"IPv4,omitempty"`
	IPv6 net.IP `json:"IPv6,omitempty"`
	Mask byte   `json:"mask,omitempty"`
}

func (ie UEIP) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x5d, 0x00, 0x00, 0x00})

	var flag byte = 0x00
	if ie.Dest {
		flag = flag | 0x04
	}

	if ie.IPv4 != nil {
		if ie.IPv4.IsUnspecified() {
			flag = flag | 0x10
		} else {
			flag = flag | 0x02
			buf.Write(ie.IPv4.To4())
		}
	}
	if ie.IPv6 != nil {
		if ie.IPv6.IsUnspecified() {
			flag = flag | 0x20
		} else {
			flag = flag | 0x01
			buf.Write(ie.IPv6.To16())
		}
		if ie.Mask == 0 {
		} else if ie.Mask < 64 {
			flag = flag | 0x08
			buf.WriteByte(64 - ie.Mask)
		} else {
			flag = flag | 0x40
			buf.WriteByte(ie.Mask)
		}
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	data[4] = flag
	b.Write(data)
}

func (ie *UEIP) decode(b []byte) (e error) {
	buf := bytes.NewReader(b)
	var flag byte

	if flag, e = buf.ReadByte(); e != nil {
		return
	}
	if flag&0x30 != 0x00 {
		e = fmt.Errorf("invalid data")
		return
	}
	ie.Dest = (flag & 0x04) == 0x04
	if flag&0x01 == 0x01 {
		ie.IPv4 = []byte{0, 0, 0, 0}
		_, e = buf.Read(ie.IPv4)
		if e != nil {
			return
		}
	}
	if flag&0x02 == 0x02 {
		ie.IPv6 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		_, e = buf.Read(ie.IPv6)
		if e != nil {
			return
		}
		if flag&0x08 == 0x08 {
			ie.Mask, e = buf.ReadByte()
			if e != nil {
				return
			}
			ie.Mask = 64 - ie.Mask
		} else if flag&0x40 == 0x40 {
			ie.Mask, e = buf.ReadByte()
			if e != nil {
				return
			}
		}
	}
	return
}

func decodeCause(data []byte) byte {
	if len(data) == 0 {
		return 0
	}
	return data[0]
}

func encodeCause(c byte, b *bytes.Buffer) {
	b.Write([]byte{0x00, 0x13, 0x00, 0x01, c})
}
