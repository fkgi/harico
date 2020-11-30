package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

var (
	con     *net.UDPConn
	tun     = make(map[uint64]*session)
	seq     = make(chan uint32, 1)
	txStack = make(map[uint32]chan Message)

	recovery = time.Now()
	waitTime = time.Second * 3
	hbTime   = time.Second * 60
)

type session struct {
	seid    uint64
	nodeid  string
	rxStack chan ReportRequest
}

// Message of PFCP
type Message struct {
	MessageType byte
	SessionID   uint64
	Sequence    uint32
	Priority    byte
	IEs         []IE
}

// IE of PFCP
type IE struct {
	IEType uint16
	Data   []byte
}

func writeMessage(data []byte) (Message, error) {
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)

	q := <-seq
	seq <- q + 1
	ch := make(chan Message)
	txStack[q] = ch
	if data[0] == 0x20 {
		data[4] = byte(q >> 16)
		data[5] = byte(q >> 8)
		data[6] = byte(q)
	} else {
		data[12] = byte(q >> 16)
		data[13] = byte(q >> 8)
		data[14] = byte(q)
	}

	log.Printf("Tx PFCP: request")
	_, e := con.Write(data)
	if e != nil {
		log.Printf("Tx PFCP: failed to write: %s", e)
		delete(txStack, q)
		return Message{}, e
	}

	t := time.AfterFunc(waitTime, func() {
		ch <- Message{}
	})
	m := <-ch
	t.Stop()

	if m.MessageType == 0 {
		e = fmt.Errorf("request timeout")
		log.Printf("Tx PFCP: failed to write: %s", e)
	} else if m.MessageType != data[1]+1 {
		e = fmt.Errorf("invalid message (type=%d) from peer", m.MessageType)
	}

	return m, e
}

func readMessage() {
	data := make([]byte, 65536)
	var n uint16

	for {
		l, e := con.Read(data)
		if e != nil {
			break
		}
		buf := bytes.NewReader(data[:l])
		var flg byte

		if flg, e = buf.ReadByte(); e != nil {
			log.Printf("Rx PFCP: failed to read header option: %s", e)
			continue
		}
		if flg != 0x20 && flg != 0x21 {
			log.Printf("Rx PFCP: invalid header options %d", flg)
			continue
		}

		m := Message{}
		if m.MessageType, e = buf.ReadByte(); e != nil {
			log.Printf("Rx PFCP: failed to read message type: %s", e)
			continue
		}
		switch m.MessageType {
		case 1, 2, 4, 6, 8, 10, 11, 12:
		case 51, 53, 55, 56:
		default:
			log.Printf("Rx PFCP: unsupported message type: %d", m.MessageType)
			continue
		}

		if e = binary.Read(buf, binary.BigEndian, &n); e != nil {
			log.Printf("Rx PFCP: failed to read message length: %s", e)
			continue
		}
		if int(n) != buf.Len() {
			log.Printf("Rx PFCP: invalid message length value: %d", n)
			continue
		}

		if flg&0x01 == 0x01 {
			if e = binary.Read(buf, binary.BigEndian, &m.SessionID); e != nil {
				log.Printf("Rx PFCP: failed to read session ID: %s", e)
				continue
			}
		}
		if e = binary.Read(buf, binary.BigEndian, &m.Sequence); e != nil {
			log.Printf("Rx PFCP: failed to read message sequence: %s", e)
			continue
		}
		m.Priority = byte(m.Sequence>>4) & 0x0f
		m.Sequence = m.Sequence >> 8

		m.IEs = []IE{}
		for buf.Len() > 0 {
			ie := IE{}
			if e = binary.Read(buf, binary.BigEndian, &ie.IEType); e != nil {
				break
			}
			if e = binary.Read(buf, binary.BigEndian, &n); e != nil {
				break
			}
			ie.Data = make([]byte, int(n))
			if l, e = buf.Read(ie.Data); e != nil {
				break
			}
			if l != len(ie.Data) {
				e = io.ErrUnexpectedEOF
				break
			}
			m.IEs = append(m.IEs, ie)
		}
		if e != nil {
			log.Printf("Rx PFCP: failed to read IEs: %s", e)
			continue
		}

		switch m.MessageType {
		case 1:
			log.Printf("Rx PFCP: heartbeat request")
			handleHeartbeat(m)
		case 12:
			log.Printf("Rx PFCP: node report request")
			// NodeReport handling
		case 56:
			log.Printf("Rx PFCP: session report request")
			handleSessionReport(m)
		default:
			log.Printf("Rx PFCP: response")
			if ch, ok := txStack[m.Sequence]; ok {
				ch <- m
			}
		}
	}
	return
}

func dialPFCP(laddr, raddr string) (e error) {
	var ra, la *net.UDPAddr
	if la, e = net.ResolveUDPAddr("udp", laddr); e != nil {
		return
	}
	if ra, e = net.ResolveUDPAddr("udp", raddr); e != nil {
		return
	}
	if con, e = net.DialUDP("udp", la, ra); e != nil {
		return
	}

	seq <- 0

	go readMessage()

	buf := bytes.NewBuffer([]byte{
		0x20, 0x05,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00})
	nodeID(buf)
	recoveryTimeStamp(buf)
	buf.Write([]byte{0x00, 0x59, 0x00, 0x01, 0x00})
	// alternativeSMFIPAddress(buf)
	// smfSetID(buf)
	// pfcpSessionRetentionInformation(buf)
	// gtpuPathQosControlInformation(buf)
	// clockDriftControlInformation(buf)

	msg, e := writeMessage(buf.Bytes())
	if e != nil {
		con.Close()
		return
	}

	for _, ie := range msg.IEs {
		switch ie.IEType {
		case 19:
			if ie.Data[0] != 1 {
				e = fmt.Errorf("failure response %d", ie.Data[0])
				con.Close()
				return
			}
		}
	}

	go heartbeat()

	return
}

func heartbeat() {
	ticker := time.NewTicker(hbTime)
	for {
		select {
		case <-ticker.C:
			buf := bytes.NewBuffer([]byte{
				0x20, 0x01,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00})
			recoveryTimeStamp(buf)
			// a.sourceIPAddress(buf)

			_, e := writeMessage(buf.Bytes())
			if e != nil {
				log.Printf("Tx PFCP: heartbeat handling failed: %s", e)
				return
			}
		}
	}
}

func handleHeartbeat(m Message) {
	buf := bytes.NewBuffer([]byte{
		0x20, 0x02,
		0x00, 0x00,
		byte(m.Sequence >> 16), byte(m.Sequence >> 8), byte(m.Sequence), 0x00})
	recoveryTimeStamp(buf)

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)

	_, e := con.Write(data)
	if e != nil {
		log.Printf("Rx PFCP: heartbeat handling failed: %s", e)
	}
}

func closePFCP() {
	for id, t := range tun {
		buf := bytes.NewBuffer([]byte{
			0x21, 0x36,
			0x00, 0x00})
		binary.Write(buf, binary.BigEndian, t.seid)
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

		writeMessage(buf.Bytes())
		delete(tun, id)
	}

	buf := bytes.NewBuffer([]byte{
		0x20, 0x09,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00})
	nodeID(buf)

	_, e := writeMessage(buf.Bytes())
	if e != nil {
		con.Close()
		return
	}

	con.Close()
}

func nodeID(b *bytes.Buffer) {
	b.Write([]byte{0x00, 0x3c})

	if addr, ok := con.LocalAddr().(*net.UDPAddr); !ok {
		b.Write([]byte{0x00, 0x00})
	} else if ip := addr.IP.To4(); ip != nil {
		b.Write([]byte{0x00, 0x05, 0x00})
		b.Write(ip)
	} else if ip = addr.IP.To16(); ip != nil {
		b.Write([]byte{0x00, 0x11, 0x01})
		b.Write(ip)
	} else {
		b.Write([]byte{0x00, 0x00})
	}
}

func recoveryTimeStamp(b *bytes.Buffer) {
	d := recovery.Sub(time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC))
	d /= 1000000000
	b.Write([]byte{0x00, 0x60, 0x00, 0x04})
	binary.Write(b, binary.BigEndian, uint32(d))
}
