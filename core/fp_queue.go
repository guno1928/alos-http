//go:build linux

package core

import (
	"sync/atomic"
	"unsafe"
)

type mpscNode struct {
	next unsafe.Pointer
}

type mpscQueue struct {
	head unsafe.Pointer
	tail unsafe.Pointer
	stub mpscNode
}

func (q *mpscQueue) init() {
	q.head = unsafe.Pointer(&q.stub)
	q.tail = unsafe.Pointer(&q.stub)
}

func (q *mpscQueue) push(n *mpscNode) {
	atomic.StorePointer(&n.next, nil)
	prev := (*mpscNode)(atomic.SwapPointer(&q.head, unsafe.Pointer(n)))
	atomic.StorePointer(&prev.next, unsafe.Pointer(n))
}

func (q *mpscQueue) pop() *mpscNode {
	tail := (*mpscNode)(q.tail)
	next := (*mpscNode)(atomic.LoadPointer(&tail.next))
	if tail == &q.stub {
		if next == nil {
			return nil
		}
		q.tail = unsafe.Pointer(next)
		tail = next
		next = (*mpscNode)(atomic.LoadPointer(&tail.next))
	}
	if next != nil {
		q.tail = unsafe.Pointer(next)
		return tail
	}
	if unsafe.Pointer(tail) != atomic.LoadPointer(&q.head) {
		return nil
	}
	q.push(&q.stub)
	next = (*mpscNode)(atomic.LoadPointer(&tail.next))
	if next != nil {
		q.tail = unsafe.Pointer(next)
		return tail
	}
	return nil
}
