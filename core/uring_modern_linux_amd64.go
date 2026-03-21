//go:build linux && amd64

package core

import (
	"encoding/binary"
	"math/bits"
	"syscall"
	"unsafe"
)

type ioUringBuf struct {
	Addr uint64
	Len  uint32
	Bid  uint16
	Resv uint16
}

type ioUringBufReg struct {
	RingAddr    uint64
	RingEntries uint32
	Bgid        uint16
	Flags       uint16
	Resv        [3]uint64
}

type ioUringBufferRing struct {
	bgid    uint16
	entries uint16
	mask    uint16
	bufSize int
	ringMem []byte
	bufs    []ioUringBuf
	tail    uint16
	slab    []byte
	data    [][]byte
}

const ioUringBufRingTailOffset = 14

func newIOUringBufferRing(entries int, bufSize int, bgid uint16) (*ioUringBufferRing, error) {
	if entries < 1 {
		entries = 1
	}
	if entries > 1<<15 {
		entries = 1 << 15
	}
	if entries&(entries-1) != 0 {
		entries = 1 << bits.Len(uint(entries-1))
	}
	if bufSize < 1 {
		return nil, syscall.EINVAL
	}

	ringBytes := entries * int(unsafe.Sizeof(ioUringBuf{}))
	ringMem, err := syscall.Mmap(-1, 0, ringBytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	slabBytes := entries * bufSize
	slab, err := syscall.Mmap(-1, 0, slabBytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		_ = syscall.Munmap(ringMem)
		return nil, err
	}

	group := &ioUringBufferRing{
		bgid:    bgid,
		entries: uint16(entries),
		mask:    uint16(entries - 1),
		bufSize: bufSize,
		ringMem: ringMem,
		bufs:    unsafe.Slice((*ioUringBuf)(unsafe.Pointer(unsafe.SliceData(ringMem))), entries),
		slab:    slab,
		data:    make([][]byte, entries),
	}
	for i := 0; i < entries; i++ {
		start := i * bufSize
		end := start + bufSize
		group.data[i] = slab[start:end:end]
	}
	group.publishTail()
	return group, nil
}

func (group *ioUringBufferRing) register(ring *ioUring) error {
	reg := ioUringBufReg{
		RingAddr:    uint64(uintptr(unsafe.Pointer(unsafe.SliceData(group.ringMem)))),
		RingEntries: uint32(group.entries),
		Bgid:        group.bgid,
	}
	if err := ring.register(ioUringRegisterPbufRing, uintptr(unsafe.Pointer(&reg)), 1); err != nil {
		return err
	}
	group.refillAll()
	return nil
}

func (group *ioUringBufferRing) close() {
	if group == nil {
		return
	}
	if len(group.ringMem) > 0 {
		_ = syscall.Munmap(group.ringMem)
		group.ringMem = nil
	}
	if len(group.slab) > 0 {
		_ = syscall.Munmap(group.slab)
		group.slab = nil
	}
	group.bufs = nil
	group.data = nil
	group.tail = 0
}

func (group *ioUringBufferRing) buffer(id uint16) []byte {
	if group == nil || int(id) >= len(group.data) {
		return nil
	}
	return group.data[id]
}

func (group *ioUringBufferRing) refillAll() {
	if group == nil {
		return
	}
	for i := 0; i < len(group.data); i++ {
		group.add(uint16(i))
	}
	group.publishTail()
}

func (group *ioUringBufferRing) recycle(id uint16) {
	if group == nil || int(id) >= len(group.data) {
		return
	}
	group.add(id)
	group.publishTail()
}

func (group *ioUringBufferRing) add(id uint16) {
	if group == nil || int(id) >= len(group.data) {
		return
	}
	slot := group.tail & group.mask
	buf := group.data[id]
	group.bufs[slot].Addr = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	group.bufs[slot].Len = uint32(len(buf))
	group.bufs[slot].Bid = id
	group.bufs[slot].Resv = 0
	group.tail++
}

func (group *ioUringBufferRing) publishTail() {
	if group == nil || len(group.ringMem) < ioUringBufRingTailOffset+2 {
		return
	}
	binary.LittleEndian.PutUint16(group.ringMem[ioUringBufRingTailOffset:ioUringBufRingTailOffset+2], group.tail)
}

func (ring *ioUring) prepAcceptMultishotUser(fd int, userData uint64, flags uint32) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpAccept
	sqe.FD = int32(fd)
	// The multishot accept bit lives in sqe.ioprio; accept flags stay in OpFlags.
	sqe.Ioprio = ioUringAcceptMultishot
	sqe.OpFlags = flags
	sqe.UserData = userData
	return nil
}

func (ring *ioUring) prepRecvMultishotUser(fd int, bgid uint16, userData uint64, pollFirst bool) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpRecv
	sqe.Ioprio = ioUringRecvMultishot
	if pollFirst {
		sqe.Ioprio |= ioUringPollFirst
	}
	sqe.Flags = ioUringSqeBufferSelect
	sqe.FD = int32(fd)
	sqe.Len = 0
	sqe.UserData = userData
	// buf_group shares storage with buf_index in the UAPI union.
	sqe.BufIndex = bgid
	return nil
}

func cqeBufferID(flags uint32) uint16 {
	return uint16(flags >> ioUringCqeBufferShift)
}
