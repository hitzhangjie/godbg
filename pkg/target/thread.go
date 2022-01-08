package target

// Thread 线程信息
type Thread struct {
	Tid     int              // thread ID
	Process *DebuggedProcess // process this thread belongs to
}
