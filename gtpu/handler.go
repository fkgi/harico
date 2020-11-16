package gtpu

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
)

var (
	// TimeEcho istime of echo interval
	TimeEcho time.Duration = 60 * time.Second
)

// Handler handles GTP-U tunnels
type Handler struct {
	tun map[uint32]*tunnel // key = local TEID
	con *net.UDPConn
	seq uint16 // packet sequence number
}

type tunnel struct {
	address   *net.UDPAddr // remote Addr
	tunDevice *os.File     // unix tun device
	flowID    byte         // current QoS Flow ID
}

// StartHandler make Handler with local address
func StartHandler(addr string) (handler Handler, err error) {
	var a *net.UDPAddr
	if a, err = net.ResolveUDPAddr("udp", addr); err != nil {
		return
	} else if handler.con, err = net.ListenUDP("udp", a); err != nil {
		return
	}
	handler.tun = make(map[uint32]*tunnel)
	handler.seq = uint16(rand.Uint32())

	go func() {
		b := make([]byte, 1500)
		for {
			if n, a, err := handler.con.ReadFromUDP(b); err != nil {
				log.Println(err)
				break
			} else if err = handler.decapsulate(a, b[:n]); err != nil {
				log.Println(err)
			}
		}
		log.Printf("GTP handler on %s is closed", addr)
	}()

	go func() {
		for {
			time.Sleep(TimeEcho)

			ips := make([]net.IP, 0)

			for _, t := range handler.tun {
				flg := false
				for _, ip := range ips {
					if ip.Equal(t.address.IP) {
						flg = true
						break
					}
				}
				if flg {
					continue
				}
				ips = append(ips, t.address.IP)

				handler.seq++
				_, err = handler.con.WriteToUDP(
					[]byte{
						0x32, 0x01,
						0x00, 0x04,
						0x00, 0x00, 0x00, 0x00,
						byte(handler.seq >> 8), byte(handler.seq),
						0x00, 0x00},
					t.address)
				if err != nil {
					log.Println(err)
					return
				}
			}
		}
	}()

	return
}

// Close handler
func (h *Handler) Close() {
	for id, t := range h.tun {
		delete(h.tun, id)
		t.tunDevice.Close()
	}
	h.con.Close()
}

func (h Handler) decapsulate(addr *net.UDPAddr, p []byte) error {
	buf := bytes.NewReader(p)

	hdr, err := buf.ReadByte()
	if err != nil {
		return err
	}
	if hdr&0x30 != 0x30 {
		return fmt.Errorf("invalid header 0x%x", hdr)
	}
	if hdr&0x01 != 0 {
		return fmt.Errorf("unsupported header flags 0x%x", hdr)
	}

	mtype, err := buf.ReadByte()
	if err != nil {
		return err
	}
	switch mtype {
	case 0x01:
		// ToDo: echo request handling
	case 0x02:
		// ToDo: echo response handling
		return nil
	case 0x1a:
		// ToDo: error indication handling
		return nil
	case 0x1f:
		// ToDo: supported extension headers notification handling
		return nil
	case 0xfe:
		// ToDo: end marker handling
	case 0xff:
		// ToDo: message handling
	default:
		return fmt.Errorf("unsupported message type 0x%x", mtype)
	}

	l := make([]byte, 2)
	n, err := buf.Read(l)
	if err != nil {
		return err
	}
	if n != len(l) {
		return io.ErrUnexpectedEOF
	}
	// ToDo: not care length

	q := make([]byte, 4)
	n, err = buf.Read(q)
	if err != nil {
		return err
	}
	if n != len(q) {
		return io.ErrUnexpectedEOF
	}
	var id uint32
	id = uint32(q[0])
	id = (id << 8) | uint32(q[1])
	id = (id << 8) | uint32(q[2])
	id = (id << 8) | uint32(q[3])

	var seq uint16
	// var qfi byte
	if hdr&0x06 != 0 {
		n, err = buf.Read(q)
		if err != nil {
			return err
		}
		if n != len(q) {
			return io.ErrUnexpectedEOF
		}
		seq = uint16(q[0])
		seq = (seq << 8) | uint16(q[1])

		switch q[3] {
		case 0x85:
			n, err = buf.Read(q)
			if err != nil {
				return err
			}
			if n != len(q) {
				return io.ErrUnexpectedEOF
			}

			// qfi = q[2] & 0x3f
			_, err = buf.Seek(int64(q[0])*4, io.SeekCurrent)
			if err != nil {
				return err
			}
		}
	}

	switch mtype {
	case 0x01:
		_, err = h.con.WriteToUDP(
			[]byte{
				0x32, 0x02,
				0x00, 0x06,
				0x00, 0x00, 0x00, 0x00,
				byte(seq >> 8), byte(seq),
				0x00, 0x00,
				0x0e, 0x00},
			addr)
	case 0xff:
		if tun, ok := h.tun[id]; !ok {
			err = fmt.Errorf("unknown TEID %d", id)
		} else if !addr.IP.Equal(tun.address.IP) {
			err = fmt.Errorf("invalid peer %s for TEID %d", addr, id)
		} else {
			_, err = tun.tunDevice.ReadFrom(buf)
		}
	}
	return err
}

// Bind GTP-U tunnel on this handler and tun device
func (h *Handler) Bind(id uint32, addr, ifname string) (lid uint32, err error) {
	t := &tunnel{flowID: 255}
	t.address, err = net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	t.tunDevice, err = getTunFile(ifname)
	if err != nil {
		return
	}

	for {
		lid = rand.Uint32()
		if _, ok := h.tun[lid]; !ok {
			h.tun[lid] = t
			break
		}
	}

	go func() {
		b := make([]byte, 1500)
		for {
			n, err := t.tunDevice.Read(b)
			if err != nil {
				break
			}

			f := byte(0x30)
			l := n
			if t.flowID < 64 {
				f = 0x34
				l += 8
			}
			buf := bytes.NewBuffer([]byte{
				f, 0xff,
				byte(l >> 8), byte(l),
				byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
			if t.flowID < 64 {
				buf.Write([]byte{
					0x00, 0x00, 0x00, 0x85,
					0x01, 0x10, t.flowID, 0x00})
			}
			buf.Write(b[:n])
			_, err = h.con.WriteToUDP(buf.Bytes(), t.address)
			if err != nil {
				break
			}
		}
	}()
	return
}

// Unbind specified GTP-U tunnel on this handler
func (h *Handler) Unbind(id uint32) error {
	t, ok := h.tun[id]
	if !ok {
		return fmt.Errorf("unknown IEID %d", id)
	}
	delete(h.tun, id)
	t.tunDevice.Close()
	return nil
}

// SetFlowIDto assign QoS Flow ID to specified tunnel
// QoS Flow ID will be unassigned if flow > 63
func (h *Handler) SetFlowIDto(id uint32, flow uint8) error {
	t, ok := h.tun[id]
	if !ok {
		return fmt.Errorf("unknown IEID %d", id)
	}
	if flow > 63 {
		flow = 255
	}
	t.flowID = flow
	return nil
}
