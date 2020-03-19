package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcutils/bipAddr"
	walletseed "github.com/btcutils/createwallet/seed"
	"github.com/btcutils/model"
	"github.com/btcutils/txauthor"
	"os"
	"strings"
	"unicode"
)

var (
	utxo     string
	seedword string
	address  string
	amount   float64
	net      int
)

var (
	activeNetParams                  = &chaincfg.MainNetParams
	coinType        bipAddr.CoinType = bipAddr.CoinTypeBTC
)

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Println("\t -utxo  utxo的hex表示")
	fmt.Println("\t -word  助记词")
	fmt.Println("\t -address  目标地址")
	fmt.Println("\t -amount  转账数量")
	fmt.Println("\t -net  网络环境 0:主网 1:测试网 2:私人网")
}

// 7a68fdb4656447c1dd9a3cd6d68216c50111ccc5433593372b4bbfa7e4b9fcf1
// bdee18d8d62fd9edaea21967ae71d8fb1dec02420ea8ddb6d5478cf7a6b14796
func main() {
	flag.StringVar(&utxo, "utxo", "", "utxo的hex表示")
	flag.StringVar(&seedword, "word", "", "助记词或种子")
	flag.StringVar(&address, "address", "", "目标地址")
	flag.Float64Var(&amount, "amount", 0, "转账数量")
	flag.IntVar(&net, "net", 0, "网络环境 0:主网 1:测试网")
	flag.Parse()
	if utxo == "" || seedword == "" || address == "" || amount < 0 || net < 0 || net > 2 {
		usage()
		return
	}

	utxos, err := ParseUTXO(utxo)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if net == 1 {
		activeNetParams = &chaincfg.TestNet3Params
		coinType = bipAddr.TypeTestnet
	}

	compress := true // generate a compressed public key
	seedword, err = ParseSeed(seedword)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	km, err := bipAddr.NewKeyManager(seedword)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	_, err = km.GetMasterKey()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//fmt.Printf("\n%-18s %s\n", "BIP39 Mnemonic:", km.GetMnemonic())
	//fmt.Printf("%-18s %x\n", "BIP39 Seed:", km.GetSeed())
	//fmt.Printf("%-18s %s\n", "BIP32 Root Key:", masterKey.B58Serialize())

	//fmt.Printf("\n%-18s %-34s %s\n", "Path(BIP49)", "SegWit(nested)", "WIF(Wallet Import Format)")
	//fmt.Println(strings.Repeat("-", 106))
	key, err := km.GetKey(bipAddr.PurposeBIP49, coinType, 0, 0, 0)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	btcwif, _, _, segwitNested, err := key.Encode(compress, activeNetParams)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//fmt.Printf("%-18s %s %s\n", key.GetPath(), segwitNested.EncodeAddress(), btcwif.String())

	if amount < 0 || amount == 0 {
		fmt.Println("请发送大于0的btc数量")
		return
	}

	amt, err := btcutil.NewAmount(amount)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// Mock up map of address and amount pairs.
	pairs := map[string]btcutil.Amount{
		address: amt,
	}
	inputSource := txauthor.MakeSendDataInputSource(segwitNested, utxos)
	changeSource := func() ([]byte, error) {
		// Derive the change output script.  As a hack to allow
		// spending from the imported account, change addresses are
		// created from account 0.
		return txscript.PayToAddrScript(segwitNested)
	}
	tx, err := txauthor.SendPairs(pairs, activeNetParams, inputSource, changeSource)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if tx.ChangeIndex >= 0 {
		tx.RandomizeChangePosition()
	}
	keys := make(map[string]*btcutil.WIF)
	keys[segwitNested.EncodeAddress()] = btcwif
	getKey := txscript.KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
		return btcwif.PrivKey, btcwif.CompressPubKey, nil
	})

	err = tx.AddAllInputScripts(activeNetParams, getKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = txauthor.ValidateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	var buf bytes.Buffer
	buf.Grow(tx.Tx.SerializeSize())
	// All returned errors (not OOM, which panics) encounted during
	// bytes.Buffer writes are unexpected.
	if err = tx.Tx.Serialize(&buf); err != nil {
		panic(err)
	}

	fmt.Println("txhash:  ", tx.Tx.TxHash())
	fmt.Println("RawTransation:  ", hex.EncodeToString(buf.Bytes()))
}

func ParseUTXO(utxoStr string) ([]model.UTXO, error) {
	hexx, err := hex.DecodeString(utxoStr)
	if err != nil {
		return nil, err
	}
	var utxo []model.UTXO
	err = json.Unmarshal(hexx, &utxo)
	if err != nil {
		return nil, err
	}
	return utxo, nil
}

func ParseSeed(seedword string) (word string, err error) {
	seedStrTrimmed := strings.TrimSpace(seedword)
	seedStrTrimmed = collapseSpace(seedStrTrimmed)
	wordCount := strings.Count(seedStrTrimmed, " ") + 1
	if wordCount != 1 {
		return seedStrTrimmed, nil
	} else {
		seed, err := hex.DecodeString(seedword)
		if err != nil {
			return "", fmt.Errorf("Invalid seed specified.  Must be a "+
				"hexadecimal value that is at least %d bits and "+
				"at most %d bits\n", hdkeychain.MinSeedBytes*8,
				hdkeychain.MaxSeedBytes*8)
		}
		word, err = walletseed.EncodeMnemonic(seed)
		if err != nil || len(seed) < hdkeychain.MinSeedBytes ||
			len(seed) > hdkeychain.MaxSeedBytes {

			fmt.Printf("Invalid seed specified.  Must be a "+
				"hexadecimal value that is at least %d bits and "+
				"at most %d bits\n", hdkeychain.MinSeedBytes*8,
				hdkeychain.MaxSeedBytes*8)
			return "", fmt.Errorf("Invalid seed specified.  Must be a "+
				"hexadecimal value that is at least %d bits and "+
				"at most %d bits\n", hdkeychain.MinSeedBytes*8,
				hdkeychain.MaxSeedBytes*8)
		}
		return word, nil
	}
}

// collapseSpace takes a string and replaces any repeated areas of whitespace
// with a single space character.
func collapseSpace(in string) string {
	whiteSpace := false
	out := ""
	for _, c := range in {
		if unicode.IsSpace(c) {
			if !whiteSpace {
				out = out + " "
			}
			whiteSpace = true
		} else {
			out = out + string(c)
			whiteSpace = false
		}
	}
	return out
}
