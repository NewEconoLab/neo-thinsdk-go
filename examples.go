package main

import (
	"github.com/neo-thinsdk-go/Neo"
	"math/big"
	"crypto/ecdsa"
)

func NeoTransfer() (string, bool) {
	params := &Neo.CreateSignParams{}
	params.Version = 1
	params.PriKey = "L4RmQvd6PVzBTgYLpYagknNjhZxsHBbJq4ky7Zd3vB7AguSM7gF1"
	params.From = "ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7"
	params.To = "APxpKoFCfBk8RjkRdKwyUnsBntDRXLYAZc"
	params.AssetId = "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b"
	params.Value = 100000000

	utxoList := []Neo.Utxo{}
	utxo := Neo.Utxo{}
	utxo.Hash = "b80f65fc5c0cc9a24ae2d613770202aae95dfa598f6541f75987b747eb5ca830"
	utxo.Value = 10000000000
	utxo.N = 0
	utxoList = append(utxoList, utxo)

	params.Utxos = utxoList

	raw, ok := Neo.CreateContractTransaction(params)
	println(raw, ok)

	return raw, ok
}

func Nep5Transfer() (string, bool)  {
	params := &Neo.CreateSignParams{}
	params.Version = 1
	params.PriKey = "L4RmQvd6PVzBTgYLpYagknNjhZxsHBbJq4ky7Zd3vB7AguSM7gF1"
	params.From = "ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7"
	params.To = "ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7"
	params.AssetId = "602c79718b16e442de58778e148d0b1084e3b2dffd5de6b7b16cee7969282de7"
	params.Value = 0

	var value = big.NewInt(100000000)
	data, _ := Neo.GetNep5Transfer("c88acaae8a0362cdbdedddf0083c452a3a8bb7b8", "ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7", "APxpKoFCfBk8RjkRdKwyUnsBntDRXLYAZc", *value)
	params.Data = data

	utxoList := []Neo.Utxo{}
	utxo := Neo.Utxo{}
	utxo.Hash = "d233d677aee8164cffc5ffa0699920d9dda9d4f5a8c23ca074641777e2a00f3b"
	utxo.Value = 900000000
	utxo.N = 0
	utxoList = append(utxoList, utxo)

	params.Utxos = utxoList

	raw, ok := Neo.CreateInvocationTransaction(params)
	println(raw, ok)

	return raw, ok
}

func main()  {
	priv, _ := Neo.NewSigningKey()
	wif := Neo.PrivateToWIF(priv)
	println(wif)

	address := Neo.PublicToAddress(&priv.PublicKey)
	println(address)

	//ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7
	priv2 := &ecdsa.PrivateKey{}
	Neo.FromWIF(priv2,"L4RmQvd6PVzBTgYLpYagknNjhZxsHBbJq4ky7Zd3vB7AguSM7gF1")
	address2 := Neo.PublicToAddress(&priv2.PublicKey)
	println(address2)

	NeoTransfer()

	//Nep5Transfer()
}