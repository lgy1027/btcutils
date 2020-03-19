package model

type UTXO struct {
	Hash        string `json:"tx_hash"`
	Height      int32  `json:"block_height"`
	TxInput     int32  `json:"tx_input_n"`
	TxOutput    uint32 `json:"tx_output_n"`
	Value       int    `json:"value"`
	RefBalance  int32  `json:"ref_balance"`
	Spent       bool   `json:"spent"`
	Confirm     int    `json:"confirmations"`
	Confirmed   string `json:"confirmed"`
	DoubleSpend bool   `json:"double_spend"`
}
