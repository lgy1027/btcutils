package wordlist

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

var testData = []struct {
	mnemonics string
	data      []byte
}{
	{
		mnemonics: "tortoise believe device spy carbon picnic riot general brass mobile believe cabbage leisure buzz guess",
		data: []byte{0xE5, 0x82, 0x94, 0xF2, 0xE9, 0xA2, 0x27, 0x48,
			0x6E, 0x8B, 0x06, 0x1B, 0x31, 0xCC, 0x52, 0x8F, 0xD7,
			0xFA, 0x3F, 0x19},
	},
}

func TestMnemonic_GetSentence(t *testing.T) {
	//seed, _ := hdkeychain.GenerateSeed(32)
	newRandomMnemonic, err := NewMnemonic(testData[0].data)
	fmt.Println("Hex:", hex.EncodeToString(testData[0].data))
	if err != nil {
		fmt.Println(err)
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(strings.Split(newRandomMnemonic, " "))
	fmt.Println("=========================")
	seed, err := EntropyFromMnemonic(newRandomMnemonic)
	for i := range testData[0].data {
		if seed[i] != testData[0].data[i] {
			fmt.Println(false)
			return
		}
	}
	fmt.Println("over......")
}
