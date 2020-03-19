// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package txauthor provides transaction creation code for wallets.
package txauthor

import (
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcutils/model"
)

// DefaultRelayFeePerKb is the default minimum relay fee policy for a mempool.
const DefaultRelayFeePerKb btcutil.Amount = 1e3

// Worst case script and input/output size estimates.
const (
	// RedeemP2PKHSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script that redeems a compressed P2PKH output.
	// It is calculated as:
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	RedeemP2PKHSigScriptSize = 1 + 73 + 1 + 33

	// P2PKHPkScriptSize is the size of a transaction output script that
	// pays to a compressed pubkey hash.  It is calculated as:
	//
	//   - OP_DUP
	//   - OP_HASH160
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	//   - OP_EQUALVERIFY
	//   - OP_CHECKSIG
	P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1

	// RedeemP2PKHInputSize is the worst case (largest) serialize size of a
	// transaction input redeeming a compressed P2PKH output.  It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 107
	//   - 107 bytes signature script
	//   - 4 bytes sequence
	RedeemP2PKHInputSize = 32 + 4 + 1 + RedeemP2PKHSigScriptSize + 4

	// P2PKHOutputSize is the serialize size of a transaction output with a
	// P2PKH output script.  It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 25
	//   - 25 bytes P2PKH output script
	P2PKHOutputSize = 8 + 1 + P2PKHPkScriptSize

	// P2WPKHPkScriptSize is the size of a transaction output script that
	// pays to a witness pubkey hash. It is calculated as:
	//
	//   - OP_0
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	P2WPKHPkScriptSize = 1 + 1 + 20

	// P2WPKHOutputSize is the serialize size of a transaction output with a
	// P2WPKH output script. It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 22
	//   - 22 bytes P2PKH output script
	P2WPKHOutputSize = 8 + 1 + P2WPKHPkScriptSize

	// RedeemP2WPKHScriptSize is the size of a transaction input script
	// that spends a pay-to-witness-public-key hash (P2WPKH). The redeem
	// script for P2WPKH spends MUST be empty.
	RedeemP2WPKHScriptSize = 0

	// RedeemP2WPKHInputSize is the worst case size of a transaction
	// input redeeming a P2WPKH output. It is calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte encoding empty redeem script
	//   - 0 bytes redeem script
	//   - 4 bytes sequence
	RedeemP2WPKHInputSize = 32 + 4 + 1 + RedeemP2WPKHScriptSize + 4

	// RedeemNestedP2WPKHScriptSize is the worst case size of a transaction
	// input script that redeems a pay-to-witness-key hash nested in P2SH
	// (P2SH-P2WPKH). It is calculated as:
	//
	//   - 1 byte compact int encoding value 22
	//   - OP_0
	//   - 1 byte compact int encoding value 20
	//   - 20 byte key hash
	RedeemNestedP2WPKHScriptSize = 1 + 1 + 1 + 20

	// RedeemNestedP2WPKHInputSize is the worst case size of a
	// transaction input redeeming a P2SH-P2WPKH output. It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 23
	//   - 23 bytes redeem script (scriptSig)
	//   - 4 bytes sequence
	RedeemNestedP2WPKHInputSize = 32 + 4 + 1 +
		RedeemNestedP2WPKHScriptSize + 4

	// RedeemP2WPKHInputWitnessWeight is the worst case weight of
	// a witness for spending P2WPKH and nested P2WPKH outputs. It
	// is calculated as:
	//
	//   - 1 wu compact int encoding value 2 (number of items)
	//   - 1 wu compact int encoding value 73
	//   - 72 wu DER signature + 1 wu sighash
	//   - 1 wu compact int encoding value 33
	//   - 33 wu serialized compressed pubkey
	RedeemP2WPKHInputWitnessWeight = 1 + 1 + 73 + 1 + 33
)

// SumOutputValues sums up the list of TxOuts and returns an Amount.
func SumOutputValues(outputs []*wire.TxOut) (totalOutput btcutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += btcutil.Amount(txOut.Value)
	}
	return totalOutput
}

// InputSource provides transaction inputs referencing spendable outputs to
// construct a transaction outputting some target amount.  If the target amount
// can not be satisified, this can be signaled by returning a total amount less
// than the target or by returning a more detailed error implementing
// InputSourceError.
type InputSource func(target btcutil.Amount) (total btcutil.Amount, inputs []*wire.TxIn,
	inputValues []btcutil.Amount, scripts [][]byte, err error)

// InputSourceError describes the failure to provide enough input value from
// unspent transaction outputs to meet a target amount.  A typed error is used
// so input sources can provide their own implementations describing the reason
// for the error, for example, due to spendable policies or locked coins rather
// than the wallet not having enough available input value.
type InputSourceError interface {
	error
	InputSourceError()
}

// Default implementation of InputSourceError.
type insufficientFundsError struct{}

func (insufficientFundsError) InputSourceError() {}
func (insufficientFundsError) Error() string {
	return "insufficient funds available to construct transaction"
}

// AuthoredTx holds the state of a newly-created transaction and the change
// output (if one was added).
type AuthoredTx struct {
	Tx              *wire.MsgTx
	PrevScripts     [][]byte
	PrevInputValues []btcutil.Amount
	TotalInput      btcutil.Amount
	ChangeIndex     int // negative if no change
}

// ChangeSource provides P2PKH change output scripts for transaction creation.
type ChangeSource func() ([]byte, error)

// RandomizeOutputPosition randomizes the position of a transaction's output by
// swapping it with a random output.  The new index is returned.  This should be
// done before signing.
func RandomizeOutputPosition(outputs []*wire.TxOut, index int) int {
	r := cprng.Int31n(int32(len(outputs)))
	outputs[r], outputs[index] = outputs[index], outputs[r]
	return int(r)
}

// RandomizeChangePosition randomizes the position of an authored transaction's
// change output.  This should be done before signing.
func (tx *AuthoredTx) RandomizeChangePosition() {
	tx.ChangeIndex = RandomizeOutputPosition(tx.Tx.TxOut, tx.ChangeIndex)
}

// SecretsSource provides private keys and redeem scripts necessary for
// constructing transaction input signatures.  Secrets are looked up by the
// corresponding Address for the previous output script.  Addresses for lookup
// are created using the source's blockchain parameters and means a single
// SecretsSource can only manage secrets for a single chain.
//
// TODO: Rewrite this interface to look up private keys and redeem scripts for
// pubkeys, pubkey hashes, script hashes, etc. as separate interface methods.
// This would remove the ChainParams requirement of the interface and could
// avoid unnecessary conversions from previous output scripts to Addresses.
// This can not be done without modifications to the txscript package.
type SecretsSource interface {
	txscript.KeyDB
	txscript.ScriptDB
	ChainParams() *chaincfg.Params
}

// AddAllInputScripts modifies transaction a transaction by adding inputs
// scripts for each input.  Previous output scripts being redeemed by each input
// are passed in prevPkScripts and the slice length must match the number of
// inputs.  Private keys and redeem scripts are looked up using a SecretsSource
// based on the previous output script.
func AddAllInputScripts(tx *wire.MsgTx, prevPkScripts [][]byte, inputValues []btcutil.Amount,
	chainParams *chaincfg.Params, key txscript.KeyDB, kdb txscript.KeyDB) error {

	inputs := tx.TxIn
	hashCache := txscript.NewTxSigHashes(tx)
	//chainParams := secrets.ChainParams()

	if len(inputs) != len(prevPkScripts) {
		return errors.New("tx.TxIn and prevPkScripts slices must " +
			"have equal length")
	}

	for i := range inputs {
		pkScript := prevPkScripts[i]

		switch {
		// If this is a p2sh output, who's script hash pre-image is a
		// witness program, then we'll need to use a modified signing
		// function which generates both the sigScript, and the witness
		// script.
		case txscript.IsPayToScriptHash(pkScript):
			err := spendNestedWitnessPubKeyHash(inputs[i], pkScript,
				int64(inputValues[i]), chainParams, nil,
				tx, hashCache, i, kdb)
			if err != nil {
				return err
			}
		case txscript.IsPayToWitnessPubKeyHash(pkScript):
			err := spendWitnessKeyHash(inputs[i], pkScript,
				int64(inputValues[i]), chainParams, nil,
				tx, hashCache, i)
			if err != nil {
				return err
			}
		default:
			sigScript := inputs[i].SignatureScript
			script, err := txscript.SignTxOutput(chainParams, tx, i,
				pkScript, txscript.SigHashAll, key, nil,
				sigScript)
			if err != nil {
				return err
			}
			inputs[i].SignatureScript = script
		}
	}

	return nil
}

// spendWitnessKeyHash generates, and sets a valid witness for spending the
// passed pkScript with the specified input amount. The input amount *must*
// correspond to the output value of the previous pkScript, or else verification
// will fail since the new sighash digest algorithm defined in BIP0143 includes
// the input value in the sighash.
func spendWitnessKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First obtain the key pair associated with this p2wkh address.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	privKey, compressed, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}
	pubKey := privKey.PubKey()

	// Once we have the key pair, generate a p2wkh address type, respecting
	// the compression type of the generated key.
	var pubKeyHash []byte
	if compressed {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeUncompressed())
	}
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}

	// With the concrete address type, we can now generate the
	// corresponding witness program to be used to generate a valid witness
	// which will allow us to spend this output.
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, true)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// spendNestedWitnessPubKey generates both a sigScript, and valid witness for
// spending the passed pkScript with the specified input amount. The generated
// sigScript is the version 0 p2wkh witness program corresponding to the queried
// key. The witness stack is identical to that of one which spends a regular
// p2wkh output. The input amount *must* correspond to the output value of the
// previous pkScript, or else verification will fail since the new sighash
// digest algorithm defined in BIP0143 includes the input value in the sighash.
func spendNestedWitnessPubKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int, kdb txscript.KeyDB) error {

	// First we need to obtain the key pair related to this p2sh output.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	var (
		privKey    *btcec.PrivateKey
		pubKey     *btcec.PublicKey
		compressed bool
	)
	if kdb != nil && secrets == nil {
		privKey, compressed, err = kdb.GetKey(addrs[0])
		if err != nil {
			return err
		}
		pubKey = privKey.PubKey()
	} else {

		privKey, compressed, err = secrets.GetKey(addrs[0])
		if err != nil {
			return err
		}
		pubKey = privKey.PubKey()
	}
	var pubKeyHash []byte
	if compressed {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeUncompressed())
	}

	// Next, we'll generate a valid sigScript that'll allow us to spend
	// the p2sh output. The sigScript will contain only a single push of
	// the p2wkh witness program corresponding to the matching public key
	// of this address.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	bldr := txscript.NewScriptBuilder()
	bldr.AddData(witnessProgram)
	sigScript, err := bldr.Script()
	if err != nil {
		return err
	}
	txIn.SignatureScript = sigScript

	// With the sigScript in place, we'll next generate the proper witness
	// that'll allow us to spend the p2wkh output.
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, compressed)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// AddAllInputScripts modifies an authored transaction by adding inputs scripts
// for each input of an authored transaction.  Private keys and redeem scripts
// are looked up using a SecretsSource based on the previous output script.
func (tx *AuthoredTx) AddAllInputScripts(params *chaincfg.Params, kdb txscript.KeyDB) error {
	return AddAllInputScripts(tx.Tx, tx.PrevScripts, tx.PrevInputValues, params, kdb, kdb)
}

// validateMsgTx verifies transaction input scripts for tx.  All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func ValidateMsgTx(tx *wire.MsgTx, prevScripts [][]byte, inputValues []btcutil.Amount) error {
	hashCache := txscript.NewTxSigHashes(tx)
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(prevScript, tx, i,
			txscript.StandardVerifyFlags, nil, hashCache, int64(inputValues[i]))
		if err != nil {
			return fmt.Errorf("cannot create script engine: %s", err)
		}
		err = vm.Execute()
		if err != nil {
			return fmt.Errorf("cannot validate transaction: %s", err)
		}
	}
	return nil
}

func SendPairs(amounts map[string]btcutil.Amount,
	chainParams *chaincfg.Params, inputSource InputSource, changeSource ChangeSource) (*AuthoredTx, error) {
	outputs, err := makeOutputs(amounts, chainParams)
	if err != nil {
		return nil, err
	}
	return sendOutputs(outputs, inputSource, changeSource)
}

func sendOutputs(outputs []*wire.TxOut,
	inputSource InputSource, changeSource ChangeSource) (*AuthoredTx, error) {
	// Ensure the outputs to be created adhere to the network's consensus
	// rules.
	for _, output := range outputs {
		err := CheckOutput(
			output, DefaultRelayFeePerKb,
		)
		if err != nil {
			return nil, err
		}
	}
	return NewUnsignedTransaction(outputs, inputSource, changeSource)
}

func NewUnsignedTransaction(outputs []*wire.TxOut,
	fetchInputs InputSource, fetchChange ChangeSource) (*AuthoredTx, error) {
	targetAmount := SumOutputValues(outputs)
	estimatedSize := EstimateVirtualSize(0, 1, 0, outputs, true)
	targetFee := FeeForSerializeSize(DefaultRelayFeePerKb, estimatedSize)
	for {
		inputAmount, inputs, inputValues, scripts, err := fetchInputs(targetAmount + targetFee)
		if err != nil {
			return nil, err
		}
		if inputAmount < targetAmount+targetFee {
			return nil, insufficientFundsError{}
		}

		// We count the types of inputs, which we'll use to estimate
		// the vsize of the transaction.
		var nested, p2wpkh, p2pkh int
		for _, pkScript := range scripts {
			switch {
			// If this is a p2sh output, we assume this is a
			// nested P2WKH.
			case txscript.IsPayToScriptHash(pkScript):
				nested++
			case txscript.IsPayToWitnessPubKeyHash(pkScript):
				p2wpkh++
			default:
				p2pkh++
			}
		}

		maxSignedSize := EstimateVirtualSize(p2pkh, p2wpkh,
			nested, outputs, true)
		maxRequiredFee := FeeForSerializeSize(DefaultRelayFeePerKb, maxSignedSize)
		remainingAmount := inputAmount - targetAmount
		if remainingAmount < maxRequiredFee {
			targetFee = maxRequiredFee
			continue
		}

		unsignedTransaction := &wire.MsgTx{
			Version:  wire.TxVersion,
			TxIn:     inputs,
			TxOut:    outputs,
			LockTime: 0,
		}
		changeIndex := -1
		changeAmount := inputAmount - targetAmount - maxRequiredFee
		if changeAmount != 0 && !IsDustAmount(changeAmount,
			P2WPKHPkScriptSize, DefaultRelayFeePerKb) {
			changeScript, err := fetchChange()
			if err != nil {
				return nil, err
			}
			//if len(changeScript) > P2WPKHPkScriptSize {
			//	return nil, errors.New("fee estimation requires change " +
			//		"scripts no larger than P2WPKH output scripts")
			//}
			change := wire.NewTxOut(int64(changeAmount), changeScript)
			l := len(outputs)
			unsignedTransaction.TxOut = append(outputs[:l:l], change)
			changeIndex = l
		}

		return &AuthoredTx{
			Tx:              unsignedTransaction,
			PrevScripts:     scripts,
			PrevInputValues: inputValues,
			TotalInput:      inputAmount,
			ChangeIndex:     changeIndex,
		}, nil
	}
}

// FeeForSerializeSize calculates the required fee for a transaction of some
// arbitrary size given a mempool's relay fee policy.
func FeeForSerializeSize(relayFeePerKb btcutil.Amount, txSerializeSize int) btcutil.Amount {
	fee := relayFeePerKb * btcutil.Amount(txSerializeSize) / 1000

	if fee == 0 && relayFeePerKb > 0 {
		fee = relayFeePerKb
	}

	if fee < 0 || fee > btcutil.MaxSatoshi {
		fee = btcutil.MaxSatoshi
	}

	return fee
}

// EstimateVirtualSize returns a worst case virtual size estimate for a
// signed transaction that spends the given number of P2PKH, P2WPKH and
// (nested) P2SH-P2WPKH outputs, and contains each transaction output
// from txOuts. The estimate is incremented for an additional P2PKH
// change output if addChangeOutput is true.
func EstimateVirtualSize(numP2PKHIns, numP2WPKHIns, numNestedP2WPKHIns int,
	txOuts []*wire.TxOut, addChangeOutput bool) int {
	changeSize := 0
	outputCount := len(txOuts)
	if addChangeOutput {
		// We are always using P2WPKH as change output.
		changeSize = P2WPKHOutputSize
		outputCount++
	}

	// Version 4 bytes + LockTime 4 bytes + Serialized var int size for the
	// number of transaction inputs and outputs + size of redeem scripts +
	// the size out the serialized outputs and change.
	baseSize := 8 +
		wire.VarIntSerializeSize(
			uint64(numP2PKHIns+numP2WPKHIns+numNestedP2WPKHIns)) +
		wire.VarIntSerializeSize(uint64(len(txOuts))) +
		numP2PKHIns*RedeemP2PKHInputSize +
		numP2WPKHIns*RedeemP2WPKHInputSize +
		numNestedP2WPKHIns*RedeemNestedP2WPKHInputSize +
		SumOutputSerializeSizes(txOuts) +
		changeSize

	// If this transaction has any witness inputs, we must count the
	// witness data.
	witnessWeight := 0
	if numP2WPKHIns+numNestedP2WPKHIns > 0 {
		// Additional 2 weight units for segwit marker + flag.
		witnessWeight = 2 +
			wire.VarIntSerializeSize(
				uint64(numP2WPKHIns+numNestedP2WPKHIns)) +
			numP2WPKHIns*RedeemP2WPKHInputWitnessWeight +
			numNestedP2WPKHIns*RedeemP2WPKHInputWitnessWeight
	}

	// We add 3 to the witness weight to make sure the result is
	// always rounded up.
	return baseSize + (witnessWeight+3)/blockchain.WitnessScaleFactor
}

// SumOutputSerializeSizes sums up the serialized size of the supplied outputs.
func SumOutputSerializeSizes(outputs []*wire.TxOut) (serializeSize int) {
	for _, txOut := range outputs {
		serializeSize += txOut.SerializeSize()
	}
	return serializeSize
}

func MakeSendDataInputSource(address btcutil.Address, utxos []model.UTXO) InputSource {
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0)
	currentScripts := make([][]byte, 0)
	currentInputValues := make([]btcutil.Amount, 0)
	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		for currentTotal < target && len(utxos) != 0 {
			nextCredit := &utxos[0]
			utxos = utxos[1:]
			hash, err := chainhash.NewHashFromStr(nextCredit.Hash)
			if err != nil {
				return currentTotal, nil, nil, nil, err
			}
			pkscript, err := txscript.PayToAddrScript(address)
			if err != nil {
				return currentTotal, nil, nil, nil, err
			}
			nextInput := wire.NewTxIn(wire.NewOutPoint(hash, nextCredit.TxOutput), nil, nil)
			currentTotal += btcutil.Amount(nextCredit.Value)
			currentInputs = append(currentInputs, nextInput)
			currentScripts = append(currentScripts, pkscript)
			currentInputValues = append(currentInputValues, btcutil.Amount(nextCredit.Value))
		}
		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
	}
}

// Transaction rule violations
var (
	ErrAmountNegative   = errors.New("transaction output amount is negative")
	ErrAmountExceedsMax = errors.New("transaction output amount exceeds maximum value")
	ErrOutputIsDust     = errors.New("transaction output is dust")
)

// CheckOutput performs simple consensus and policy tests on a transaction
// output.
func CheckOutput(output *wire.TxOut, relayFeePerKb btcutil.Amount) error {
	if output.Value < 0 {
		return ErrAmountNegative
	}
	if output.Value > btcutil.MaxSatoshi {
		return ErrAmountExceedsMax
	}
	if IsDustOutput(output, relayFeePerKb) {
		return ErrOutputIsDust
	}
	return nil
}

// IsDustOutput determines whether a transaction output is considered dust.
// Transactions with dust outputs are not standard and are rejected by mempools
// with default policies.
func IsDustOutput(output *wire.TxOut, relayFeePerKb btcutil.Amount) bool {
	// Unspendable outputs which solely carry data are not checked for dust.
	if txscript.GetScriptClass(output.PkScript) == txscript.NullDataTy {
		return false
	}

	// All other unspendable outputs are considered dust.
	if txscript.IsUnspendable(output.PkScript) {
		return true
	}

	return IsDustAmount(btcutil.Amount(output.Value), len(output.PkScript),
		relayFeePerKb)
}

// IsDustAmount determines whether a transaction output value and script length would
// cause the output to be considered dust.  Transactions with dust outputs are
// not standard and are rejected by mempools with default policies.
func IsDustAmount(amount btcutil.Amount, scriptSize int, relayFeePerKb btcutil.Amount) bool {
	return amount < GetDustThreshold(scriptSize, relayFeePerKb)
}

// GetDustThreshold is used to define the amount below which output will be
// determined as dust. Threshold is determined as 3 times the relay fee.
func GetDustThreshold(scriptSize int, relayFeePerKb btcutil.Amount) btcutil.Amount {
	// Calculate the total (estimated) cost to the network.  This is
	// calculated using the serialize size of the output plus the serial
	// size of a transaction input which redeems it.  The output is assumed
	// to be compressed P2PKH as this is the most common script type.  Use
	// the average size of a compressed P2PKH redeem input (148) rather than
	// the largest possible (txsizes.RedeemP2PKHInputSize).
	totalSize := 8 + wire.VarIntSerializeSize(uint64(scriptSize)) +
		scriptSize + 148

	byteFee := relayFeePerKb / 1000
	relayFee := btcutil.Amount(totalSize) * byteFee
	return 3 * relayFee
}

// makeOutputs creates a slice of transaction outputs from a pair of address
// strings to amounts.  This is used to create the outputs to include in newly
// created transactions from a JSON object describing the output destinations
// and amounts.
func makeOutputs(pairs map[string]btcutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, len(pairs))
	for addrStr, amt := range pairs {
		addr, err := btcutil.DecodeAddress(addrStr, chainParams)
		if err != nil {
			return nil, fmt.Errorf("cannot decode address: %s", err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, fmt.Errorf("cannot create txout script: %s", err)
		}

		outputs = append(outputs, wire.NewTxOut(int64(amt), pkScript))
	}
	return outputs, nil
}
