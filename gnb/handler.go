package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
)

// BindTunnel data
type BindTunnel struct {
	ID     uint32 `json:"ID"`
	Device string `json:"device"`
	IP     net.IP `json:"IP"`
}

func handleSessionPOST(w http.ResponseWriter, r *http.Request) {
	d := BindTunnel{}
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

	d.ID, e = h.Bind(d.ID, d.IP.String()+":2152", d.Device)
	if e != nil {
		log.Println("GTP-U tunnel binding failed:", e)
		errorResponse(w, ProblemDetails{
			Title:    "GTP-U tunnel binding failed",
			Status:   http.StatusInternalServerError,
			Detail:   e.Error(),
			Instance: r.URL.Path})
		return
	}

	ip, _, _ := net.SplitHostPort(l)
	d.IP = net.ParseIP(ip)

	b, _ = json.Marshal(d)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location",
		"/gtp-an/v1/session/"+strconv.FormatUint(uint64(d.ID), 16))
	w.WriteHeader(http.StatusCreated)
	w.Write(b)
}

// Modify data
type Modify struct {
	FlowID byte `json:"flowID"`
}

func handleSessionPATCH(w http.ResponseWriter, r *http.Request, id uint32) {
	d := Modify{}
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

	e = h.SetFlowIDto(id, d.FlowID)
	if e != nil {
		log.Println("GTP-U tunnel modification failed:", e)
		errorResponse(w, ProblemDetails{
			Title:    "GTP-U tunnel modification failed",
			Status:   http.StatusInternalServerError,
			Detail:   e.Error(),
			Instance: r.URL.Path})
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleSessionDELETE(w http.ResponseWriter, r *http.Request, id uint32) {
	e := h.Unbind(id)
	if e != nil {
		log.Println("GTP-U tunnel unbinding failed:", e)
		errorResponse(w, ProblemDetails{
			Title:    "GTP-U tunnel unbinding failed",
			Status:   http.StatusInternalServerError,
			Detail:   e.Error(),
			Instance: r.URL.Path})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
