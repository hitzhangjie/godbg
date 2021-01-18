package main

import "fmt"

func p() {
	i := 20
	i += 44
	fmt.Printf("%d\n", i)
}

func main() {
	p()
	return
}

