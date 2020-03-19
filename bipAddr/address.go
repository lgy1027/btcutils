package bipAddr

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"sync"
)

type Purpose = uint32

const (
	PurposeBIP44 Purpose = 0x8000002C // 44' BIP44
	PurposeBIP49 Purpose = 0x80000031 // 49' BIP49
	PurposeBIP84 Purpose = 0x80000054 // 84' BIP84
)

type CoinType = uint32

const (
	CoinTypeBTC CoinType = 0x80000000
	TypeTestnet CoinType = 0x80000001
	CoinTypeLTC CoinType = 0x80000002
	CoinTypeETH CoinType = 0x8000003c
	CoinTypeEOS CoinType = 0x800000c2
)

const (
	Apostrophe uint32 = 0x80000000 // 0'
)

type Key struct {
	path     string
	bip32Key *bip32.Key
}

func (k *Key) Encode(compress bool, activeNetParams *chaincfg.Params) (btcwif *btcutil.WIF,
	addressPubKey *btcutil.AddressPubKey, segwitBech32 *btcutil.AddressWitnessPubKeyHash,
	segwitNested *btcutil.AddressScriptHash, err error) {
	prvKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), k.bip32Key.Key)
	return GenerateFromBytes(prvKey, compress, activeNetParams)
}

func (k *Key) GetPath() string {
	return k.path
}

type KeyManager struct {
	mnemonic   string
	passphrase string
	keys       map[string]*bip32.Key
	mux        sync.Mutex
}

func NewKeyManager(mnemonic string) (*KeyManager, error) {
	//entropy, err := bip39.NewEntropy(bitSize)
	//if err != nil {
	//	return nil, err
	//}
	//mnemonic, err := bip39.NewMnemonic(entropy)
	//if err != nil {
	//	return nil, err
	//}
	km := &KeyManager{
		mnemonic:   mnemonic,
		passphrase: "",
		keys:       make(map[string]*bip32.Key, 0),
	}
	return km, nil
}

func (km *KeyManager) GetMnemonic() string {
	return km.mnemonic
}

func (km *KeyManager) GetPassphrase() string {
	return km.passphrase
}

func (km *KeyManager) GetSeed() []byte {
	return bip39.NewSeed(km.GetMnemonic(), km.GetPassphrase())
}

func (km *KeyManager) getKey(path string) (*bip32.Key, bool) {
	km.mux.Lock()
	defer km.mux.Unlock()

	key, ok := km.keys[path]
	return key, ok
}

func (km *KeyManager) setKey(path string, key *bip32.Key) {
	km.mux.Lock()
	defer km.mux.Unlock()

	km.keys[path] = key
}

func (km *KeyManager) GetMasterKey() (*bip32.Key, error) {
	path := "m"

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	key, err := bip32.NewMasterKey(km.GetSeed())
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetPurposeKey(purpose uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'`, purpose-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetMasterKey()
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(purpose)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetCoinTypeKey(purpose, coinType uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetPurposeKey(purpose)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(coinType)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetAccountKey(purpose, coinType, account uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe, account)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetCoinTypeKey(purpose, coinType)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(account + Apostrophe)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

// GetChangeKey ...
// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#change
// change constant 0 is used for external chain
// change constant 1 is used for internal chain (also known as change addresses)
func (km *KeyManager) GetChangeKey(purpose, coinType, account, change uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetAccountKey(purpose, coinType, account)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(change)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetKey(purpose, coinType, account, change, index uint32) (*Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change, index)

	key, ok := km.getKey(path)
	if ok {
		return &Key{path: path, bip32Key: key}, nil
	}

	parent, err := km.GetChangeKey(purpose, coinType, account, change)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(index)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return &Key{path: path, bip32Key: key}, nil
}

func Generate(compress bool, activeNetParams *chaincfg.Params) (btcwif *btcutil.WIF,
	addressPubKey *btcutil.AddressPubKey, segwitBech32 *btcutil.AddressWitnessPubKeyHash, segwitNested *btcutil.AddressScriptHash, err error) {
	prvKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return GenerateFromBytes(prvKey, compress, activeNetParams)
}

func GenerateFromBytes(prvKey *btcec.PrivateKey, compress bool, activeNetParams *chaincfg.Params) (btcwif *btcutil.WIF,
	addressPubKey *btcutil.AddressPubKey, segwitBech32 *btcutil.AddressWitnessPubKeyHash, segwitNested *btcutil.AddressScriptHash, err error) {
	// generate the wif(wallet import format) string
	btcwif, err = btcutil.NewWIF(prvKey, activeNetParams, compress)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	//wif = btcwif.String()

	// generate a normal p2pkh address
	serializedPubKey := btcwif.SerializePubKey()
	addressPubKey, err = btcutil.NewAddressPubKey(serializedPubKey, activeNetParams)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	//address = addressPubKey.EncodeAddress()

	// generate a normal p2wkh address from the pubkey hash
	witnessProg := btcutil.Hash160(serializedPubKey)
	segwitBech32, err = btcutil.NewAddressWitnessPubKeyHash(witnessProg, activeNetParams)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	//segwitBech32 = addressWitnessPubKeyHash.EncodeAddress()

	// generate an address which is
	// backwards compatible to Bitcoin nodes running 0.6.0 onwards, but
	// allows us to take advantage of segwit's scripting improvments,
	// and malleability fixes.
	serializedScript, err := txscript.PayToAddrScript(segwitBech32)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	segwitNested, err = btcutil.NewAddressScriptHash(serializedScript, activeNetParams)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	//segwitNested = addressScriptHash.EncodeAddress()

	return btcwif, addressPubKey, segwitBech32, segwitNested, nil
}
