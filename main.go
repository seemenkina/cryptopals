package main

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/seemenkina/cryptopals/set2"
)

func main(){
	encr, _ := set2.Chall10("chl10.txt")
	spew.Dump(string(encr))
}
