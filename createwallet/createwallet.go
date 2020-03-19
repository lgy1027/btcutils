// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/btcsuite/btcutil/hdkeychain"
	gseed "github.com/btcutils/createwallet/seed"
	"github.com/btcutils/createwallet/wallet"
	"os"
	"path/filepath"
	"strings"
)

const (
	showHelpMessage = "Specify -h to show available options"
)

// usage displays the general usage when the help flag is not displayed and
// and an invalid command was specified.  The commandUsage function is used
// instead when a valid command was specified.
func usage(errorMessage string) {
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	fmt.Fprintln(os.Stderr, errorMessage)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  %s [OPTIONS]\n\n",
		appName)
	fmt.Fprintln(os.Stderr, showHelpMessage)
}

func main() {
	_, _, err := loadConfig()
	if err != nil {
		os.Exit(1)
	}

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil || len(seed) < hdkeychain.MinSeedBytes ||
		len(seed) > hdkeychain.MaxSeedBytes {
		fmt.Fprintf(os.Stderr, "Failed to GenerateSeed result: %v", err)
		os.Exit(1)
	}
	seedStrSplit, err := gseed.EncodeMnemonicSlice(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "EncodeMnemonicSlice is faild,seed:%x", seed)
		os.Exit(1)
	}
	chainParams := activeNetParams
	addresses, _, _, err := wallet.GetAddressAndPri(seed, chainParams)
	fmt.Println("Your wallet generation seed is:")
	count := len(seedStrSplit)
	for i := 0; i < count; i++ {
		fmt.Printf("%v ", seedStrSplit[i])

		if (i+1)%6 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\nHex: %x\n", seed)
	fmt.Printf("\nAddress: %s\n", addresses[0].String())
}
