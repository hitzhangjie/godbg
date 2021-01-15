package symbol

import "github.com/hitzhangjie/godbg/target"

// DebuggedProcess debugged process
type DebuggedProcess struct {
	target *target.TargetProcess // 目标层操作
	bi     *BinaryInfo           // 符号层操作
}

func NewDebuggerProcess(cmd string, args ...string) (*DebuggedProcess, error) {

	// start `cmd` as tracee
	target, err := target.NewTargetProcess(cmd, args...)
	if err != nil {
		return nil, err
	}

	// load binary ifo
	bi, err := Analyze(cmd)
	if err != nil {
		return nil, err
	}

	dbp := DebuggedProcess{
		target: target,
		bi:     bi,
	}
	return &dbp, nil
}
