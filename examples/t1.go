package main

import "fmt"

func p() {
	i := 20
	i += 44
	s := "10101010"
	fmt.Printf("%d\n", i)
	fmt.Printf("%s\n", s)
}

func main() {
	p()
	return
}
