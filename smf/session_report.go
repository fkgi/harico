package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// ReportRequest data
type ReportRequest struct {
	ReportTye struct {
		UISR bool `json:"UISR,omitempty"`
		SESR bool `json:"UESR,omitempty"`
		TMIR bool `json:"TMIR,omitempty"`
		UPIR bool `json:"UPIR,omitempty"`
		ERIR bool `json:"ERIR,omitempty"`
		USAR bool `json:"USAR,omitempty"`
		DLDR bool `json:"DLDR,omitempty"`
	} `json:"type"`
	DownlinkData *DownlinkData `json:"downlinkData,omitempty"`
	/*
		Usage
	*/
	// Error Indication Report
	// Load Control Information
	// Overload Control Information
	// Additional Usage Reports Information
	// PFCPSRReq-Flags
	// Old CP F-SEID
	// Packet Rate Status Report
	// TSC Management Information
	// Session Report
}

// ReportResponse data
type ReportResponse struct {
	// Cause
	// Offending IE
	// Update BAR
	// PFCPSRRsp-Flags
	// CP F-SEID
	// N4-u F-TEID
	// Alternative SMF IP Address
}

func handleSessionGET(w http.ResponseWriter, r *http.Request, t *session) {
	b, _ := json.Marshal(<-t.rxStack)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func handleSessionReport(m Message) {
	buf := bytes.NewBuffer([]byte{
		0x21, 0x39,
		0x00, 0x00})
	if t, ok := tun[m.SessionID]; !ok {
		buf.Write([]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			byte(m.Sequence >> 16), byte(m.Sequence >> 8), byte(m.Sequence),
			0x00})
		encodeCause(65, buf)
	} else {
		binary.Write(buf, binary.BigEndian, t.seid)
		buf.Write([]byte{
			byte(m.Sequence >> 16), byte(m.Sequence >> 8), byte(m.Sequence),
			0x00})
		encodeCause(1, buf)
		// Offending IE
		// Update BAR
		// PFCPSRRsp-Flags
		// CP F-SEID
		// N4-u F-TEID
		// Alternative SMF IP Address

		req := ReportRequest{}
		for _, ie := range m.IEs {
			switch ie.IEType {
			case 39:
				req.ReportTye.DLDR = ie.Data[0]&0x01 == 0x01
				req.ReportTye.USAR = ie.Data[0]&0x02 == 0x02
				req.ReportTye.ERIR = ie.Data[0]&0x04 == 0x04
				req.ReportTye.UPIR = ie.Data[0]&0x08 == 0x08
				req.ReportTye.TMIR = ie.Data[0]&0x10 == 0x10
				req.ReportTye.SESR = ie.Data[0]&0x20 == 0x20
				req.ReportTye.UISR = ie.Data[0]&0x40 == 0x40
			case 83:
				req.DownlinkData = &DownlinkData{}
				if e := req.DownlinkData.decode(ie.Data); e != nil {
					break
				}
			case 80:
			}
		}
		t.rxStack <- req
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)

	_, e := con.Write(data)
	if e != nil {
		log.Println(e)
	}
}

// DownlinkData IE
type DownlinkData struct {
	ID   uint16 `json:"ID"`
	QFI  byte   `json:"QFI,omitempty"`
	PPI  byte   `json:"PPI,omitempty"`
	BUFF bool   `json:"BUFF,omitempty"`
	DROP bool   `json:"DROP,omitempty"`
}

func (ie *DownlinkData) decode(b []byte) (e error) {
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
		case 45:
			l = 1
			if b[0]&0x01 == 0x01 {
				ie.PPI = b[l] & 0x3f
				l++
			}
			if b[0]&0x02 == 0x02 {
				ie.QFI = b[l] & 0x3f
			}
		case 260:
			ie.DROP = b[0]&0x01 == 0x01
			ie.BUFF = b[0]&0x02 == 0x02
		}
		if e != nil {
			break
		}
	}
	return
}
