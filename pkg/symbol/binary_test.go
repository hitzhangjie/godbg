package symbol

import "testing"

func TestAnalyze(t *testing.T) {
	bi, err := Analyze("../../examples/t1")
	if err != nil {
		t.Fatal(err)
	}
	bi.Dump()
	pc, err := bi.FileLineToPC("/root/debugger101/godbg/examples/t1.go", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pc: %#x", pc)
}
