// @File   : wallet.go
// @Author : liguoyu
// @Date: 2020/1/3 16:04
package wallet

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
)

// KeyScope represents a restricted key scope from the primary root key within
// the HD chain. From the root manager (m/) we can create a nearly arbitrary
// number of ScopedKeyManagers of key derivation path: m/purpose'/cointype'.
// These scoped managers can then me managed indecently, as they house the
// encrypted cointype key and can derive any child keys from there on.
type KeyScope struct {
	// Purpose is the purpose of this key scope. This is the first child of
	// the master HD key.
	Purpose uint32

	// Coin is a value that represents the particular coin which is the
	// child of the purpose key. With this key, any accounts, or other
	// children can be derived at all.
	Coin uint32
}

const (
	// maxCoinType is the maximum allowed coin type used when structuring
	// the BIP0044 multi-account hierarchy.  This value is based on the
	// limitation of the underlying hierarchical deterministic key
	// derivation.
	maxCoinType = hdkeychain.HardenedKeyStart - 1

	// MaxAccountNum is the maximum allowed account number.  This value was
	// chosen because accounts are hardened children and therefore must not
	// exceed the hardened child range of extended keys and it provides a
	// reserved account at the top of the range for supporting imported
	// addresses.
	MaxAccountNum = hdkeychain.HardenedKeyStart - 2 // 2^31 - 2
)

// deriveCoinTypeKey derives the cointype key which can be used to derive the
// extended key for an account according to the hierarchy described by BIP0044
// given the coin type key.
//
// In particular this is the hierarchical deterministic extended key path:
// m/purpose'/<coin type>'
func deriveCoinTypeKey(masterNode *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {

	var KeyScopeBIP0044 = KeyScope{
		Purpose: 44,
		Coin:    0,
	}
	// Enforce maximum coin type.
	if KeyScopeBIP0044.Coin > maxCoinType {
		return nil, fmt.Errorf("coin type may not exceed")
	}

	// The hierarchy described by BIP0043 is:
	//  m/<purpose>'/*
	//
	// This is further extended by BIP0044 to:
	//  m/44'/<coin type>'/<account>'/<branch>/<address index>
	//
	// However, as this is a generic key store for any family for BIP0044
	// standards, we'll use the custom scope to govern our key derivation.
	//
	// The branch is 0 for external addresses and 1 for internal addresses.

	// Derive the purpose key as a child of the master node.
	purpose, err := masterNode.Child(KeyScopeBIP0044.Purpose + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	// Derive the coin type key as a child of the purpose key.
	coinTypeKey, err := purpose.Child(KeyScopeBIP0044.Coin + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	return coinTypeKey, nil
}

// deriveAccountKey derives the extended key for an account according to the
// hierarchy described by BIP0044 given the master node.
//
// In particular this is the hierarchical deterministic extended key path:
//   m/purpose'/<coin type>'/<account>'
func deriveAccountKey(coinTypeKey *hdkeychain.ExtendedKey,
	account uint32) (*hdkeychain.ExtendedKey, error) {

	// Enforce maximum account number.
	if account > MaxAccountNum {
		return nil, fmt.Errorf("account number may not exceed")
	}

	// Derive the account key as a child of the coin type key.
	return coinTypeKey.Child(account + hdkeychain.HardenedKeyStart)
}

func GetAddressAndPri(seed []byte, chainParams *chaincfg.Params) ([]btcutil.Address, *hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	rootKey, err := hdkeychain.NewMaster(seed, chainParams)
	if err != nil {
		str := "failed to derive master extended key"
		return nil, nil, nil, fmt.Errorf(str)
	}

	coinTypeKeyPriv, err := deriveCoinTypeKey(rootKey)
	if err != nil {
		return nil, nil, nil, err
	}
	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, 0)
	if err != nil {
		return nil, nil, nil, err
	}

	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		return nil, nil, nil, err
	}
	branchKey, err := acctKeyPub.Child(0)
	if err != nil {
		return nil, nil, nil, err
	}
	branchKeyPriv, err := acctKeyPriv.Child(0)
	if err != nil {
		return nil, nil, nil, err
	}

	idxKey, err := branchKey.Child(0)
	if err != nil {
		return nil, nil, nil, err
	}
	idxKeyPriv, err := branchKeyPriv.Child(0)
	if err != nil {
		return nil, nil, nil, err
	}

	address, err := idxKey.Address(chainParams)
	if err != nil {
		return nil, nil, nil, err
	}
	addrs := make([]btcutil.Address, 0, 1)
	addrs = append(addrs, address)
	return addrs, idxKey, idxKeyPriv, nil
}
