package main

import (
	"bytes"
	"encoding/binary"
)

// CreateURR IE
type CreateURR struct {
	ID       uint32 `json:"ID"`
	Method   Method `json:"measurementMethod"`
	Triggers []byte `json:"reportingTriggers"`
	/*
		MeasurementPeriod
	*/
	VolumeThreshold *VolumeThreshold `json:"volumeThreshold,omitempty"`
	/*
		VolumeQuota
		// Event Threshold
		// Event Quota
		TimeThreshold
		TimeQuota
		QuotaHoldingTime
		// Dropped DL Traffic Threshold
		QuotaValidityTime
		// Monitoring Time
		// Subsequent Volume Threshold
		// Subsequent Time Threshold
		// Subsequent Volume Quota
		// Subsequent Time Quota
		// Subsequent Event Threshold
		// Subsequent Event Quota
		InactivityDetectionTime
		// Linked URRID
		// Measurement Information
		// FAR ID for Quota Action
		// Ethernet Inactivity Timer
		// Additional Monitoring Time
		// Number of Reports
	*/
}

func (ie CreateURR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x06, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x51, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	ie.Method.encode(buf)

	buf.Write([]byte{0x00, 0x25,
		byte(len(ie.Triggers) >> 8), byte(len(ie.Triggers))})
	buf.Write(ie.Triggers)

	if ie.VolumeThreshold != nil {
		ie.VolumeThreshold.encode(buf)
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// RemoveURR IE
type RemoveURR struct {
	ID uint32 `json:"ID"`
}

func (ie RemoveURR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x4d, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x51, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// UpdateURR IE
type UpdateURR struct {
	ID       uint32  `json:"ID"`
	Method   *Method `json:"measurementMethod,omitempty"`
	Triggers []byte  `json:"reportingTriggers,omitempty"`
	/*
		MeasurementPeriod
	*/
	VolumeThreshold *VolumeThreshold `json:"volumeThreshold,omitempty"`
	/*
		VolumeQuota
		TimeThreshold
		TimeQuota
		// Event Threshold
		// Event Quota
		QuotaHoldingTime
		// Dropped DL Traffic Threshold
		QuotaValidityTime
		// Monitoring Time
		// Subsequent Volume Threshold
		// Subsequent Time Threshold
		// Subsequent Volume Quota
		// Subsequent Time Quota
		// Subsequent Event Threshold
		// Subsequent Event Quota
		InactivityDetectionTime
		// Linked URR ID
		// Measurement Information
		// FAR ID for Quota Action
		// Ethernet Inactivity Timer
		// Additional Monitoring Time
		// Number of Reports
	*/
}

func (ie UpdateURR) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x0d, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x51, 0x00, 0x04})
	binary.Write(buf, binary.BigEndian, ie.ID)

	if ie.Method != nil {
		ie.Method.encode(buf)
	}

	if ie.Triggers != nil {
		buf.Write([]byte{0x00, 0x25,
			byte(len(ie.Triggers) >> 8), byte(len(ie.Triggers))})
		buf.Write(ie.Triggers)
	}

	if ie.VolumeThreshold != nil {
		ie.VolumeThreshold.encode(buf)
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	b.Write(data)
}

// Method IE
type Method struct {
	Duration bool `json:"duration,omitempty"`
	Volume   bool `json:"volume,omitempty"`
	Event    bool `json:"event,omitempty"`
}

func (ie Method) encode(b *bytes.Buffer) {
	b.Write([]byte{0x00, 0x3e, 0x00, 0x01})
	var m byte = 0x00
	if ie.Duration {
		m = m | 0x01
	}
	if ie.Volume {
		m = m | 0x02
	}
	if ie.Event {
		m = m | 0x04
	}
	b.WriteByte(m)
}

// VolumeThreshold IE
type VolumeThreshold struct {
	Total    uint64 `json:"total,omitempty"`
	Uplink   uint64 `json:"uplink,omitempty"`
	Downlink uint64 `json:"downlink,omitempty"`
}

func (ie VolumeThreshold) encode(b *bytes.Buffer) {
	buf := bytes.NewBuffer([]byte{0x00, 0x1f, 0x00, 0x00, 0x00})

	var flag byte = 0
	if ie.Total != 0 {
		flag |= 0x01
		binary.Write(buf, binary.BigEndian, ie.Total)
	}
	if ie.Uplink != 0 {
		flag |= 0x02
		binary.Write(buf, binary.BigEndian, ie.Uplink)
	}
	if ie.Downlink != 0 {
		flag |= 0x04
		binary.Write(buf, binary.BigEndian, ie.Downlink)
	}

	data := buf.Bytes()
	l := len(data) - 4
	data[2] = byte(l >> 8)
	data[3] = byte(l)
	data[4] = flag
	b.Write(data)
}
