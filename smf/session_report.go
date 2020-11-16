package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net/http"
)

func handleSessionGET(w http.ResponseWriter, r *http.Request, t *session) {
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
		// Update BAR
		// PFCPSRRsp-Flags
		// CP F-SEID
		// N4-u F-TEID
		// Alternative SMF IP Address
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
