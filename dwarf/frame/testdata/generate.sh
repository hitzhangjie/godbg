#!/bin/bash -e

go build -gcflags="all=-N -l" -ldflags="-compressdwarf=false" -o main main.go

objcopy --only-section=.debug_frame main main.frame
