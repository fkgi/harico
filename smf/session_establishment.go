package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strconv"
)

// EstablishmentRequest data
type EstablishmentRequest struct {
	// Node ID
	// CP F-SEID
	PDR []CreatePDR `json:"PDR"`
	FAR []CreateFAR `json:"FAR"`
	URR []CreateURR `json:"URR,omitempty"`
	QER []CreateQER `json:"QER,omitempty"`
	BAR *CreateBAR  `json:"BAR,omitempty"`
	// Create Traffic Endpoint
	PDNType         PDNType `json:"pdnType,omitempty"`
	InactivityTimer uint32  `json:"inactivityTimer,omitempty"`
	// User ID
	// Trace Information
	DNN string `json:"DNN,omitempty"`
	// MAR
	// PFCPSEReq-Flags
	// Create Bridge Info for TSC string
	// SRR
	// Provide ATSSS Control Information
	TimeStamp bool    `json:"timeStamp,omitempty"`
	SNSSAI    *SNSSAI `json:"SNSSAI,omitempty"`
	// Provide RDS configuration information
}

// EstablishmentResponse data
type EstablishmentResponse struct {
	ContextID string `json:"ID"`
	// Node ID
	// Cause
	// Offending IE
	// UP F-SEID
	PDR []CreatedPDR `json:"PDR,omitempty"`
	// Load Control Information
	// Overload Control Information
	// Failed Rule ID `json:"failedRuleID,omitempty"`
	// Created Traffic Endpoint
	// Created Bridge Info for TSC
	// ATSSS Control Parameters
	// RDS configuration information
}

func handleSessionPOST(w http.ResponseWriter, r *http.Request) {
	d := EstablishmentRequest{}
	b, e := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	if e != nil {
		errorResponse(w, ProblemDetails{
			Title:    "reading HTTP BODY failed",
			Status:   http.StatusInternalServerError,
			Detail:   e.Error(),
			Instance: r.URL.Path})
		return
	}
	if e = json.Unmarshal(b, &d); e != nil {
		errorResponse(w, ProblemDetails{
			Title:    "unmarshal JSON failed",
			Status:   http.StatusInternalServerError,
			Detail:   e.Error(),
			Instance: r.URL.Path})
		return
	}

	var lid uint64
	var s session
	for {
		lid = rand.Uint64()
		if _, ok := tun[lid]; !ok {
			tun[lid] = &s
			break
		}
	}

	buf := bytes.NewBuffer([]byte{
		0x21, 0x32,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00})
	nodeID(buf)
	sessionID(buf, lid)

	for _, p := range d.PDR {
		p.encode(buf)
	}
	for _, p := range d.FAR {
		p.encode(buf)
	}
	for _, p := range d.URR {
		p.encode(buf)
	}
	for _, p := range d.QER {
		p.encode(buf)
	}
	if d.BAR != nil {
		d.BAR.encode(buf)
	}
	if d.PDNType != 0 {
		d.PDNType.encode(buf)
	}
	if d.InactivityTimer != 0 {
		buf.Write([]byte{0x00, 0x75, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, d.InactivityTimer)
	}
	if len(d.DNN) != 0 {
		data := []byte(d.DNN)
		buf.Write([]byte{0x00, 0x9f, byte(len(data) >> 8), byte(len(data))})
		buf.Write(data)
	}
	if d.TimeStamp {
		recoveryTimeStamp(buf)
	}
	if d.SNSSAI != nil {
		d.SNSSAI.encode(buf)
	}

	m, e := writeMessage(buf.Bytes())
	res := EstablishmentResponse{
		ContextID: strconv.FormatUint(lid, 16)}
	if e == nil {
		var cause byte
		for _, ie := range m.IEs {
			switch ie.IEType {
			case 19:
				cause = decodeCause(ie.Data)
			case 57:
				s.seid = decodeSessionID(ie.Data)
			case 8:
				if res.PDR == nil {
					res.PDR = make([]CreatedPDR, 0)
				}
				pdr := CreatedPDR{}
				if e = pdr.decode(ie.Data); e != nil {
					break
				}
				res.PDR = append(res.PDR, pdr)
			}
		}

		if cause != 1 {
			e = fmt.Errorf("PFCP error (cause=%d) from peer", cause)
		}
	}

	if e != nil {
		errorResponse(w, ProblemDetails{
			Title:    "PFCP message handling failed",
			Status:   http.StatusInternalServerError,
			Detail:   e.Error(),
			Instance: r.URL.Path})
		return
	}

	b, _ = json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/pfcp-cp/v1/session/"+strconv.FormatUint(lid, 16))
	w.WriteHeader(http.StatusCreated)
	w.Write(b)
}

func sessionID(b *bytes.Buffer, id uint64) {
	b.Write([]byte{0x00, 0x39})

	if addr, ok := con.LocalAddr().(*net.UDPAddr); !ok {
		b.Write([]byte{0x00, 0x00})
	} else if ip := addr.IP.To4(); ip != nil {
		b.Write([]byte{0x00, 0x0d, 0x02})
		binary.Write(b, binary.BigEndian, id)
		b.Write(ip)
	} else if ip = addr.IP.To16(); ip != nil {
		b.Write([]byte{0x00, 0x19, 0x01})
		binary.Write(b, binary.BigEndian, id)
		b.Write(ip)
	} else {
		b.Write([]byte{0x00, 0x00})
	}
}

func decodeSessionID(b []byte) (id uint64) {
	buf := bytes.NewReader(b)

	if _, e := buf.ReadByte(); e != nil {
		return
	}
	binary.Read(buf, binary.BigEndian, &id)
	return
}

// PDNType IE
type PDNType int

// MarshalText returns text of ie
func (ie PDNType) MarshalText() ([]byte, error) {
	switch ie {
	case 1:
		return []byte("IPv4"), nil
	case 2:
		return []byte("IPv6"), nil
	case 3:
		return []byte("IPv4v6"), nil
	case 4:
		return []byte("Non-IP"), nil
	case 5:
		return []byte("Ethernet"), nil
	}
	return nil, fmt.Errorf("invalid PDN Type: %d", ie)
}

// UnmarshalText sets value of data to *ie.
func (ie *PDNType) UnmarshalText(data []byte) error {
	switch string(data) {
	case "IPv4":
		*ie = 1
	case "IPv6":
		*ie = 2
	case "IPv4v6":
		*ie = 3
	case "Non-IP":
		*ie = 4
	case "Ethernet":
		*ie = 5
	default:
		return fmt.Errorf("invalid PDN Type: %s", string(data))
	}
	return nil
}

func (ie PDNType) encode(b *bytes.Buffer) {
	data := []byte{0x00, 0x71, 0x00, 0x01, 0x00}
	switch ie {
	case 1:
		data[4] = 0x01
	case 2:
		data[4] = 0x02
	case 3:
		data[4] = 0x03
	case 4:
		data[4] = 0x04
	case 5:
		data[4] = 0x05
	default:
		return
	}
	b.Write(data)
}

// SNSSAI IE
type SNSSAI struct {
	SST byte `json:"sst"`
	SD  int  `json:"sd"`
	// SD is 0xFFFFFF if no SD associated with the SST
}

func (ie SNSSAI) encode(b *bytes.Buffer) {
	b.Write([]byte{0x01, 0x01, 0x00, 0x04,
		ie.SST,
		byte(ie.SD >> 16), byte(ie.SD >> 8), byte(ie.SD)})
}
