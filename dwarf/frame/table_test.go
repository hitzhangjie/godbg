package frame

import (
	"debug/elf"
	"encoding/binary"
	"testing"
)

func TestFrameDescriptionEntry_EstablishFrame(t *testing.T) {
	f, err := elf.Open("testdata/main")
	if err != nil {
		t.Fatal(err)
	}

	data, err := f.Section(".debug_frame").Data()
	if err != nil {
		t.Fatal(err)
	}

	fdes := Parse(data, binary.BigEndian, 0x0, ptrSizeByRuntimeArch())
	pc := 0x4b8221
	fde, err := fdes.FDEForPC(uint64(pc))
	if err != nil {
		t.Fatal(err)
	}

	// 现在已经根据FDE中的字节码指令构建完了FDE的CFA运算规则
	frameContext := fde.EstablishFrame(uint64(pc))
	t.Logf("loc: %#x", frameContext.loc)
	t.Logf("cfa: %v", frameContext.CFA)
	t.Logf("regs: %v", frameContext.Regs)
	t.Logf("ret: %v", frameContext.RetAddrReg)

	// 接下来主要执行CFA计算规则得到CFA的值就可以了
	// ...

}
