package main

import (
	"fmt"
	"os"

	"github.com/Cazo-Net/netpipe/internal/config"
	netpipe "github.com/Cazo-Net/netpipe/pkg"
)

func main() {
	if len(os.Args) < 2 {
		printBanner()
		config.PrintHelp("")
		os.Exit(1)
	}

	if os.Args[1] == "list-devices" {
		fmt.Println("Supported device types:")
		fmt.Println()
		netpipe.ListDevices()
		os.Exit(0)
	}

	if os.Args[1] == "list-formats" {
		netpipe.ListFormats()
		os.Exit(0)
	}

	cfg, err := config.ParseArgs(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	engine := netpipe.New(cfg)
	if err := engine.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printBanner() {
	fmt.Println(`
        _ __  _   _ _ __ ___  _ __ ___  _   _ ___
       | '_ \| | | | '_ \ / _ \| '_ \ / _ \ | | / _ \
       | | | | |_| | |_) | (_) | | | |  __/ |_| |  __/
       |_| |_|\__, | .__/ \___/|_| |_|\___|\__, |\___|
               |___/|_|                     |___/
`)
	fmt.Println("  NetPipe v1.0.0 - Network Infrastructure Configuration Parser")
	fmt.Println("  Based on nipper-ng by Ian Ventura-Whiting")
	fmt.Println("  Rewritten in Go | License: GPL v3")
	fmt.Println()
}
