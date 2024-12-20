package main

import "fmt"

func main() {
	var (
		size = 128
		char = 'A'
		str  = ""
	)
	for i := 0; i < size; i++ {
		str += string(char)
	}
	fmt.Println(str)
}
