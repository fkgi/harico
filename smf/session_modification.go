package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// ModificationRequest data
type ModificationRequest struct {
	SEID      bool        `json:"SEID,omitempty"`
	RemovePDR []RemovePDR `json:"removePDR,omitempty"`
	RemoveFAR []RemoveFAR `json:"removeFAR,omitempty"`
	RemoveURR []RemoveURR `json:"removeURR,omitempty"`
	RemoveQER []RemoveQER `json:"removeQER,omitempty"`
	RemoveBAR *RemoveBAR  `json:"removeBAR,omitempty"`
	// Remove Traffic Endpoint
	CreatePDR []CreatePDR `json:"createPDR,omitempty"`
	CreateFAR []CreateFAR `json:"createFAR,omitempty"`
	CreateURR []CreateURR `json:"createURR,omitempty"`
	CreateQER []CreateQER `json:"createQER,omitempty"`
	CreateBAR *CreateBAR  `json:"createBAR,omitempty"`
	// Create Traffic Endpoint
	UpdatePDR []UpdatePDR `json:"updatePDR,omitempty"`
	UpdateFAR []UpdateFAR `json:"updateFAR,omitempty"`
	UpdateURR []UpdateURR `json:"updateURR,omitempty"`
	UpdateQER []UpdateQER `json:"updateQER,omitempty"`
	UpdateBAR *UpdateBAR  `json:"updateBAR,omitempty"`
	// Update Traffic Endpoint
	// PFCPSMReq-Flags
	// Query URR
	InactivityTimer uint32 `json:"inactivityTimer,omitempty"`
	// Query URR Reference
	// Trace Information
	// Remove MAR
	// Update MAR
	// Create MAR
	NodeID bool `json:"nodeID,omitempty"`
	// TSC Management Information
	// Remove SRR
	// Create SRR
	// Update SRR
	// Provide ATSSS Control Information
	// Ethernet Context Information
	// Access Availability Information
	// Query Packet Rate Status
}

// ModificationResponse data
type ModificationResponse struct {
	// Cause
	// Offending IE
	CreatedPDR []CreatedPDR `json:"createdPDR,omitempty"`
	// Load Control Information
	// Overload Control Information
	// Usage Report
	// Failed Rule ID
	// Additional Usage Reports Information
	// Created/Updated Traffic Endpoint
	// TSC Management Information
	// ATSSS Control Parameters
	UpdatedPDR []UpdatedPDR `json:"updatedPDR,omitempty"`
	// Packet Rate Status Report
}

func handleSessionPATCH(w http.ResponseWriter, r *http.Request, t *session, id uint64) {
	d := ModificationRequest{}
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

	buf := bytes.NewBuffer([]byte{
		0x21, 0x34,
		0x00, 0x00})
	binary.Write(buf, binary.BigEndian, t.seid)
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	if d.SEID {
		sessionID(buf, id)
	}

	for _, p := range d.RemovePDR {
		p.encode(buf)
	}
	for _, p := range d.RemoveFAR {
		p.encode(buf)
	}
	for _, p := range d.RemoveURR {
		p.encode(buf)
	}
	for _, p := range d.RemoveQER {
		p.encode(buf)
	}
	if d.RemoveBAR != nil {
		d.RemoveBAR.encode(buf)
	}

	for _, p := range d.CreatePDR {
		p.encode(buf)
	}
	for _, p := range d.CreateFAR {
		p.encode(buf)
	}
	for _, p := range d.CreateURR {
		p.encode(buf)
	}
	for _, p := range d.CreateQER {
		p.encode(buf)
	}
	if d.CreateBAR != nil {
		d.CreateBAR.encode(buf)
	}

	for _, p := range d.UpdatePDR {
		p.encode(buf)
	}
	for _, p := range d.UpdateFAR {
		p.encode(buf)
	}
	for _, p := range d.UpdateURR {
		p.encode(buf)
	}
	for _, p := range d.UpdateQER {
		p.encode(buf)
	}
	if d.UpdateBAR != nil {
		d.UpdateBAR.encode(buf)
	}

	if d.InactivityTimer != 0 {
		buf.Write([]byte{0x00, 0x75, 0x00, 0x04})
		binary.Write(buf, binary.BigEndian, d.InactivityTimer)
	}
	if d.NodeID {
		nodeID(buf)
	}

	m, e := writeMessage(buf.Bytes())
	res := ModificationResponse{}
	if e == nil {
		var cause byte
		for _, ie := range m.IEs {
			switch ie.IEType {
			case 19:
				cause = decodeCause(ie.Data)
			case 8:
				if res.CreatedPDR == nil {
					res.CreatedPDR = make([]CreatedPDR, 0)
				}
				pdr := CreatedPDR{}
				if e = pdr.decode(ie.Data); e != nil {
					break
				}
				res.CreatedPDR = append(res.CreatedPDR, pdr)
			case 256:
				if res.UpdatedPDR == nil {
					res.UpdatedPDR = make([]UpdatedPDR, 0)
				}
				pdr := UpdatedPDR{}
				if e = pdr.decode(ie.Data); e != nil {
					break
				}
				res.UpdatedPDR = append(res.UpdatedPDR, pdr)
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
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}
