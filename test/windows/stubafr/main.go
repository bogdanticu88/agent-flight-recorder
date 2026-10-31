// Command stubafr stands in for afr.exe when testing how the Windows
// deployment scripts handle native command results. Behaviour is chosen with
// the AFR_STUB_MODE environment variable:
//
//	ok                 every command succeeds; collect writes a bundle and a matching sidecar
//	fail-version       "version" exits 1
//	fail-install       "install" exits 1
//	collect-fail       "collect" exits 1 and writes nothing
//	collect-partial    "collect" writes bundle + sidecar and exits 3
//	collect-nosidecar  "collect" writes only the bundle and exits 0
//	collect-badhash    "collect" writes a sidecar that does not match and exits 0
//
// It is test tooling only and is never shipped.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	mode := os.Getenv("AFR_STUB_MODE")
	if mode == "" {
		mode = "ok"
	}
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	switch os.Args[1] {
	case "version":
		if mode == "fail-version" {
			fmt.Fprintln(os.Stderr, "stub: version failing on purpose")
			os.Exit(1)
		}
		fmt.Println("afr stub")
	case "install":
		if mode == "fail-install" {
			fmt.Fprintln(os.Stderr, "stub: install failing on purpose")
			os.Exit(1)
		}
		fmt.Println("stub: install ok")
	case "collect":
		out := ""
		for i := 2; i < len(os.Args)-1; i++ {
			if os.Args[i] == "-o" {
				out = os.Args[i+1]
			}
		}
		if mode == "collect-fail" || out == "" {
			fmt.Fprintln(os.Stderr, "stub: collect failing on purpose")
			os.Exit(1)
		}
		data := []byte("PK stub bundle for " + filepath.Base(out))
		if err := os.WriteFile(out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		switch mode {
		case "collect-nosidecar":
			os.Exit(0)
		case "collect-badhash":
			h = "0000000000000000000000000000000000000000000000000000000000000000"
		}
		if err := os.WriteFile(out+".sha256", []byte(h+"  "+filepath.Base(out)+"\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(out)
		if mode == "collect-partial" {
			os.Exit(3)
		}
	default:
		os.Exit(0)
	}
}
