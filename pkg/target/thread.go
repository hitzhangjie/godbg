package target

import (
	"syscall"
)

// Thread 线程信息
type Thread struct {
	Tid     int                // thread ID
	Status  syscall.WaitStatus // wait status
	Process *DebuggedProcess   // process this thread belongs to
}
