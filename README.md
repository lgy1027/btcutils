signTx
======

Generate signature transaction

Support BIP 44\49\84

Run
```bash
$ ./signTx -utxo hexUtxo  -word "wordlist" -address toAddress -amount 0.1 -net 1
```

Option:
    -utxo:Hex representation
    -word:wordlist or seed
    -net:(0:mainnet  1:testnet)
