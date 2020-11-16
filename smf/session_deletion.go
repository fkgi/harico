package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
)

// DeletionRequest data
type DeletionRequest struct{}

// DeletionResponse data
type DeletionResponse struct {
	// Cause
	// Offending IE
	// Load Control Information
	// Overload Control Information
	// Usage Report
	// Additional Usage Reports Information
	// Packet Rate Status Report
	// Session Report
}

func handleSessionDELETE(w http.ResponseWriter, r *http.Request, t *session, id uint64) {
	buf := bytes.NewBuffer([]byte{
		0x21, 0x36,
		0x00, 0x00})
	binary.Write(buf, binary.BigEndian, t.seid)
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	m, e := writeMessage(buf.Bytes())
	res := DeletionResponse{}
	if e == nil {
		var cause byte
		for _, ie := range m.IEs {
			switch ie.IEType {
			case 19:
				cause = decodeCause(ie.Data)
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

	delete(tun, id)

	b, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
	w.Write(b)
}
