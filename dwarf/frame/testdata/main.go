package main

import "fmt"

func Add(a, b int) int {
	return add(a, b)
}

func add(a, b int) int {
	return a + b
}

func main() {
	fmt.Println("hello world")

	a := 1
	b := 2
	c := Add(a, b)

	fmt.Println(c)
}
