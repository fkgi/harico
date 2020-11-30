package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("starting HARICO SMF")

	la := flag.String("l", "127.0.0.2:8805", "local addr/port")
	ra := flag.String("r", "127.0.0.1:8805", "remote addr/port")
	mg := flag.String("m", ":8080", "management API addr/port")
	h := flag.Int("h", int(hbTime/time.Second), "heartbeat interval")
	flag.Parse()

	hbTime = time.Second * time.Duration(*h)
	rand.Seed(time.Now().UnixNano())

	e := dialPFCP(*la, *ra)
	if e != nil {
		log.Fatalf("Tx PFCP: faild to setup association: %s", e)
	}

	go func() {
		log.Fatalln(http.ListenAndServe(*mg, http.Handler(apiHandler)))
	}()

	sigc := make(chan os.Signal)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sigc
	log.Println("shutting down")
	closePFCP()

	log.Println("process is stopped")
}

var apiHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	buf := new(bytes.Buffer)
	fmt.Fprintln(buf, "Rx API:")
	fmt.Fprintln(buf, " | method: ", r.Method)
	fmt.Fprintln(buf, " | authority: ", r.URL.String())
	fmt.Fprintln(buf, " | body:")
	fmt.Fprintln(buf, " | |", r.Body)
	log.Print(buf.String())

	p := r.URL.Path
	if p == "" {
		p = "/"
	} else {
		if p[0] != '/' {
			p = "/" + p
		}
		np := path.Clean(p)
		if p[len(p)-1] == '/' && np != "/" {
			if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
				np = p
			} else {
				np += "/"
			}
		}
		p = np
	}

	if b, _ := path.Match("/pfcp-cp/v1/session", p); b {
		switch r.Method {
		case http.MethodPost:
			handleSessionPOST(w, r)
		case http.MethodGet:
			handleSessionLIST(w, r)
		default:
			w.Header().Set("allow", "POST, GET")
			errorResponse(w, ProblemDetails{
				Title:    "invalid method",
				Status:   http.StatusMethodNotAllowed,
				Detail:   "only POST/GET is allowed",
				Instance: r.URL.Path})
		}
	} else if b, _ := path.Match("/pfcp-cp/v1/session/*", p); b {
		id, e := strconv.ParseUint(strings.Split(p, "/")[4], 16, 64)
		if e != nil {
			errorResponse(w, ProblemDetails{
				Title:    "context not found",
				Status:   http.StatusNotFound,
				Detail:   "invalid session ID",
				Instance: r.URL.Path})
		} else if t, ok := tun[id]; !ok {
			errorResponse(w, ProblemDetails{
				Title:    "context not found",
				Status:   http.StatusNotFound,
				Detail:   "no such session",
				Instance: r.URL.Path})
		} else {
			switch r.Method {
			case http.MethodDelete:
				handleSessionDELETE(w, r, t, id)
			case http.MethodPatch:
				handleSessionPATCH(w, r, t, id)
			case http.MethodGet:
				handleSessionGET(w, r, t)
			default:
				w.Header().Set("allow", "PATCH, GET, DELETE")
				errorResponse(w, ProblemDetails{
					Title:    "invalid method",
					Status:   http.StatusMethodNotAllowed,
					Detail:   "only PATCH/GET/DELETE is allowed",
					Instance: r.URL.Path})
			}
		}
	} else {
		errorResponse(w, ProblemDetails{
			Title:    "context not found",
			Status:   http.StatusNotFound,
			Detail:   "invalid path",
			Instance: r.URL.Path})
	}
})

func errorResponse(w http.ResponseWriter, p ProblemDetails) {
	w.Header().Set("content-type", "application/problem+json")
	b, _ := json.Marshal(p)
	w.WriteHeader(p.Status)
	w.Write(b)
}

// ProblemDetails struct
type ProblemDetails struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}
