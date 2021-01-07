package target

import (
	"go.uber.org/atomic"
)

var (
	seqNo = atomic.NewUint64(0)
)

// Breakpoint 断点信息
type Breakpoint struct {
	ID      uint64  // 断点编号
	Addr    uintptr // 断点地址
	Pos     string  // 源文件位置
	Orig    byte    // 原内存数据
	Cond    string  // 条件表达式
	Enabled bool    // 断点是否启用
}

func NewBreakpoint(addr uintptr, orig byte, location string) (Breakpoint, error) {
	b := Breakpoint{
		ID:   seqNo.Add(1),
		Addr: addr,
		Orig: orig,
		Pos:  location,
	}
	return b, nil
}

type Breakpoints []Breakpoint

func (b Breakpoints) Len() int {
	return len(b)
}

func (b Breakpoints) Less(i, j int) bool {
	if b[i].ID <= b[j].ID {
		return true
	}
	return false
}

func (b Breakpoints) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}
