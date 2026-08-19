//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
)

func platformDefaultCommand() string { return "discord" }

func platformSetWindowBranding() {
	if st, err := os.Stdout.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		fmt.Print("\033]0;Discord Freedom Saiydero\007")
	}
}

func cmdWindowsSelfTest() error {
	return errors.New("winselftest is only available in the Windows build")
}
