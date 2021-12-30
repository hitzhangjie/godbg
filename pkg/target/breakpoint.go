package target

import (
	"go.uber.org/atomic"
)

var (
	bpSeqNo = atomic.NewUint64(0)
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

// 在指令地址addr处创建一个断点，该地址处原始的1字节数据为orig，源码位置为location
func newBreakPoint(addr uintptr, orig byte, location string) *Breakpoint {
	return &Breakpoint{
		ID:   bpSeqNo.Add(1),
		Addr: addr,
		Orig: orig,
		Pos:  location,
	}
}

// Breakpoints 所有的断点信息
type Breakpoints []*Breakpoint

// Len 返回长度
func (b Breakpoints) Len() int {
	return len(b)
}

// Less 检查b[i]是否小于b[j]
func (b Breakpoints) Less(i, j int) bool {
	if b[i].ID <= b[j].ID {
		return true
	}
	return false
}

// Swap 交换b[i]和b[j]
func (b Breakpoints) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}
