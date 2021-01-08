package target

import "golang.org/x/sys/unix"

type Thread struct {
	Tid     int
	Status  unix.WaitStatus
	Process *TargetProcess
}
