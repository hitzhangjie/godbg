package target

import (
	"syscall"
)

type Thread struct {
	Tid     int
	Status  syscall.WaitStatus
	Process *DebuggedProcess
}
