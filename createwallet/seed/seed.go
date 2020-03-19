// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package seed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcutils/createwallet/wordlist"
	"strings"
)

// GenerateRandomSeed returns a new seed created from a cryptographically-secure
// random source.  If the seed size is unacceptable,
// hdkeychain.ErrInvalidSeedLen is returned.
func GenerateRandomSeed(size uint) ([]byte, error) {
	if size >= uint(^uint8(0)) {
		return nil, errors.New("ErrInvalidSeedLen")
	}
	if size < hdkeychain.MinSeedBytes || size > hdkeychain.MaxSeedBytes {
		return nil, errors.New("ErrInvalidSeedLen")
	}
	seed, err := hdkeychain.GenerateSeed(uint8(size))
	if err != nil {
		return nil, err
	}
	return seed, nil
}

// checksumByte returns the checksum byte used at the end of the seed mnemonic
// encoding.  The "checksum" is the first byte of the double SHA256.
func checksumByte(data []byte) byte {
	intermediateHash := sha256.Sum256(data)
	return sha256.Sum256(intermediateHash[:])[0]
}

// EncodeMnemonicSlice encodes a seed as a mnemonic word list.
func EncodeMnemonicSlice(seed []byte) ([]string, error) {
	mnemonic, err := wordlist.NewMnemonic(seed)
	if err != nil {
		return nil, err
	}
	return strings.Split(mnemonic, " "), nil
}

// EncodeMnemonic encodes a seed as a mnemonic word list separated by spaces.
func EncodeMnemonic(seed []byte) (string, error) {
	mnemonic, err := wordlist.NewMnemonic(seed)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// DecodeUserInput decodes a seed in either hexadecimal or mnemonic word list
// encoding back into its binary form.
func DecodeUserInput(input string) ([]byte, error) {
	words := strings.Split(strings.TrimSpace(input), " ")
	var seed []byte
	switch {
	case len(words) == 1:
		// Assume hex
		var err error
		seed, err = hex.DecodeString(words[0])
		if err != nil {
			return nil, err
		}
	case len(words) > 1:
		// Assume mnemonic with encoded checksum byte
		decoded, err := wordlist.EntropyFromMnemonic(input)
		if err != nil {
			return nil, err
		}

		seed = decoded[:]
	}

	if len(seed) < hdkeychain.MinSeedBytes || len(seed) > hdkeychain.MaxSeedBytes {
		return nil, errors.New("ErrInvalidSeedLen")
	}
	return seed, nil
}
