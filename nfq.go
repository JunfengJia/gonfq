package nfq

/*
#cgo CFLAGS: -Wall
#cgo LDFLAGS: -lnetfilter_queue

#include <string.h>
#include "nfq.h"
*/
import "C"

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

type Verdict C.uint

type Verdict_data struct {
	v    Verdict
	data []byte
}

const (
	NF_DROP   Verdict = 0
	NF_ACCEPT Verdict = 1
	NF_STOLEN Verdict = 2
	NF_QUEUE  Verdict = 3
	NF_REPEAT Verdict = 4
	NF_STOP   Verdict = 5

	NFQ_DEFAULT_PACKET_SIZE uint32        = 0xffff
	NFQ_DEFAULT_TIMEOUT     time.Duration = time.Microsecond * 50
)

type Packet struct {
	Id      uint32
	Proto   uint16
	Payload []byte
	Len     uint32

	vdct     chan Verdict_data
	vdct_set bool
}

func (p *Packet) SetVerdict(vdct Verdict, pkt []byte) bool {
	if p.vdct_set {
		return false
	}

	if pkt != nil && len(pkt) > C.MAX_PKT_BUF_LEN {
		return false
	}

	p.vdct_set = true
	p.vdct <- Verdict_data{vdct, pkt}

	return true
}

type Nfq struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	timeout time.Duration
	vdct    Verdict

	pktChan      chan *Packet
	timeoutCount uint64
}

func NewNfq(queueId uint16, maxPacketsInQueue uint32, packetSize uint32, timeout time.Duration, default_action Verdict) (*Nfq, error) {
	var nfq = Nfq{timeout: timeout}
	var err error
	var ret C.int

	if nfq.h, err = C.nfq_open(); err != nil {
		return nil, fmt.Errorf("Error open nfq handle: %v\n", err)
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, C.AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error unbinding existing NFQ handler from AF_INET protocol family: %v\n", err)
	}

	if ret, err := C.nfq_bind_pf(nfq.h, C.AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error binding to AF_INET protocol family: %v\n", err)
	}

	nfq.pktChan = make(chan *Packet, maxPacketsInQueue)
	if nfq.qh, err = C.CreateQueue(nfq.h, C.u_int16_t(queueId), unsafe.Pointer(&nfq)); err != nil || nfq.qh == nil {
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Error binding to queue: %v\n", err)
	}

	if ret, err = C.nfq_set_queue_maxlen(nfq.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set max packets in queue: %v\n", err)
	}

	if C.nfq_set_mode(nfq.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set packets copy mode: %v\n", err)
	}

	if nfq.fd, err = C.nfq_fd(nfq.h); err != nil {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to get queue file-descriptor. %v", err)
	}

	go nfq.run()

	return &nfq, nil
}

func (nfq *Nfq) Packets() <-chan *Packet {
	return nfq.pktChan
}

func (nfq *Nfq) run() {
	C.Run(nfq.h, nfq.fd)
}

func (nfq *Nfq) Timeouts() uint64 {
	return nfq.timeoutCount
}

func (nfq *Nfq) Close() {
	syscall.Close((int)(nfq.fd))
	C.nfq_destroy_queue(nfq.qh)
	C.nfq_close(nfq.h)
	close(nfq.pktChan)
}

//export go_callback
func go_callback(id uint32, proto uint16, data *C.uchar, data_len C.int, nfqptr unsafe.Pointer, pkt_data *C.struct_pkt_data_t) Verdict {
	xdata := C.GoBytes(unsafe.Pointer(data), data_len)
	packet := &Packet{Id: id,
		Proto:   proto,
		Payload: xdata,
		Len:     (uint32)(data_len),
		vdct:    make(chan Verdict_data, 1)}
	nfq := (*Nfq)(nfqptr)

	nfq.pktChan <- packet
	select {
	case v := <-packet.vdct:
		if v.data != nil {
			pkt_data.len = C.uint32_t(len(v.data))
			C.memcpy(unsafe.Pointer(&pkt_data.data[0]), unsafe.Pointer(&v.data[0]), C.size_t(pkt_data.len))
		}
		return v.v
	case <-time.After(nfq.timeout):
		nfq.timeoutCount++
		return nfq.vdct
	}
}
