package frame

import (
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"
	"unsafe"
)

func ptrSizeByRuntimeArch() int {
	return int(unsafe.Sizeof(uintptr(0)))
}

func TestFDEForPC(t *testing.T) {
	frames := newFrameIndex()
	frames = append(frames,
		&FrameDescriptionEntry{begin: 10, size: 40},
		&FrameDescriptionEntry{begin: 50, size: 50},
		&FrameDescriptionEntry{begin: 100, size: 100},
		&FrameDescriptionEntry{begin: 300, size: 10})

	type arg struct {
		pc  uint64
		fde *FrameDescriptionEntry
	}

	args := []arg{
		{0, nil},
		{9, nil},
		{10, frames[0]},
		{35, frames[0]},
		{49, frames[0]},
		{50, frames[1]},
		{75, frames[1]},
		{100, frames[2]},
		{199, frames[2]},
		{200, nil},
		{299, nil},
		{300, frames[3]},
		{309, frames[3]},
		{310, nil},
		{400, nil},
	}

	for _, arg := range args {
		out, err := frames.FDEForPC(arg.pc)
		if arg.fde != nil {
			if err != nil {
				t.Fatal(err)
			}
			if out != arg.fde {
				t.Errorf("[pc = %#x] got incorrect fde\noutput:\t%#v\nexpected:\t%#v", arg.pc, out, arg.fde)
			}
		} else {
			if err == nil {
				t.Errorf("[pc = %#x] expected error got fde %#v", arg.pc, out)
			}
		}
	}
}

func BenchmarkFDEForPC(b *testing.B) {
	f, err := os.Open("testdata/frame")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		b.Fatal(err)
	}
	fdes := Parse(data, binary.BigEndian, 0, ptrSizeByRuntimeArch())

	for i := 0; i < b.N; i++ {
		// bench worst case, exhaustive search
		_, _ = fdes.FDEForPC(0x455555555)
	}
}

func TestXXX(t *testing.T) {
	f, err := os.Open("testdata/main")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	fdes := Parse(data, binary.BigEndian, 0x0, ptrSizeByRuntimeArch())
	for _, fde := range fdes {
		t.Logf("fde range from %#x to %#x", fde.begin, fde.size)
	}

	/*
		        main.go:9               0x4b81e9        488d4424d8                      lea rax, ptr [rsp-0x28]
		        main.go:9               0x4b81ee        483b4110                        cmp rax, qword ptr [rcx+0x10]
		        main.go:9               0x4b81f2        0f865c010000                    jbe 0x4b8354
		=>      main.go:9               0x4b81f8*       4881eca8000000                  sub rsp, 0xa8
		        main.go:9               0x4b81ff        4889ac24a0000000                mov qword ptr [rsp+0xa0], rbp
		        main.go:9               0x4b8207        488dac24a0000000                lea rbp, ptr [rsp+0xa0]
		        main.go:10              0x4b820f        0f57c0                          xorps xmm0, xmm0
		        main.go:10              0x4b8212        0f11442460                      movups xmmword ptr [rsp+0x60], xmm0
		        main.go:10              0x4b8217        488d442460                      lea rax, ptr [rsp+0x60]
		        main.go:10              0x4b821c        4889442458                      mov qword ptr [rsp+0x58], rax
		        main.go:10              0x4b8221        8400                            test byte ptr [rax], al
	*/

	args := []uintptr{
		0x4b820f,
		0x4b83b9,
	}

	for _, addr := range args {
		fde, err := fdes.FDEForPC(uint64(addr))
		if err != nil {
			t.Fatal()
		}
		t.Logf("found FDE, range from %#x to %#x", fde.begin, fde.begin+fde.size)
	}
}
