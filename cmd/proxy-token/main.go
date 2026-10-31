package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		fmt.Fprintln(os.Stderr, "generate token:", err)
		os.Exit(1)
	}
	hash := sha256.Sum256(token[:])
	fmt.Printf("token=%s\nsha256=%s\n", hex.EncodeToString(token[:]), hex.EncodeToString(hash[:]))
}
