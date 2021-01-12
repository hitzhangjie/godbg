#!/bin/bash -e

GOOS=linux GOARCH=amd64 go build -gcflags="all=-N -l" -ldflags="-compressdwarf=false" -o main main.go
