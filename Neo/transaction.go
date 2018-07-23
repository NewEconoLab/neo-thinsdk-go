package Neo

import (
	"bytes"
	"github.com/neo-thinsdk-go/utils"
	"encoding/binary"
	"crypto/ecdsa"
	"math/big"
	"github.com/neo-thinsdk-go/simplejson"
	//"fmt"
)

const (
	MinerTransaction byte = 0x00
	IssueTransaction byte = 0x01
	ClaimTransaction byte = 0x02
	EnrollmentTransaction byte = 0x20
	RegisterTransaction byte = 0x40
	ContractTransaction byte = 0x80
	PublishTransaction byte = 0xd0
	InvocationTransaction byte = 0xd1
)

const (
	/// <summary>
	/// 外部合同的散列值
	/// </summary>
	ContractHash byte = 0x00

	/// <summary>
	/// 用于ECDH密钥交换的公钥，该公钥的第一个字节为0x02
	/// </summary>
	ECDH02 byte = 0x02
	/// <summary>
	/// 用于ECDH密钥交换的公钥，该公钥的第一个字节为0x03
	/// </summary>
	ECDH03 byte = 0x03

	/// <summary>
	/// 用于对交易进行额外的验证
	/// </summary>
	Script byte = 0x20

	Vote byte = 0x30

	DescriptionUrl byte = 0x81
	Description    byte = 0x90

	Hash1  byte = 0xa1
	Hash2  byte = 0xa2
	Hash3  byte = 0xa3
	Hash4  byte = 0xa4
	Hash5  byte = 0xa5
	Hash6  byte = 0xa6
	Hash7  byte = 0xa7
	Hash8  byte = 0xa8
	Hash9  byte = 0xa9
	Hash10 byte = 0xaa
	Hash11 byte = 0xab
	Hash12 byte = 0xac
	Hash13 byte = 0xad
	Hash14 byte = 0xae
	Hash15 byte = 0xaf

	/// <summary>
	/// 备注
	/// </summary>
	Remark   byte = 0xf0
	Remark1  byte = 0xf1
	Remark2  byte = 0xf2
	Remark3  byte = 0xf3
	Remark4  byte = 0xf4
	Remark5  byte = 0xf5
	Remark6  byte = 0xf6
	Remark7  byte = 0xf7
	Remark8  byte = 0xf8
	Remark9  byte = 0xf9
	Remark10 byte = 0xfa
	Remark11 byte = 0xfb
	Remark12 byte = 0xfc
	Remark13 byte = 0xfd
	Remark14 byte = 0xfe
	Remark15 byte = 0xff
)

type Attribute struct {
	usage byte
	data []byte
}

const D uint64 = 100000000

type Fixed8 struct {
	value uint64
}

type TransactionOutput struct {
	assetId []byte
	value Fixed8
	toAddress []byte
}

type TransactionInput struct {
	hash []byte
	index uint16
}

type Witness struct {
	InvocationScript []byte
	VerificationScript []byte
}

type IExtData interface {
	Serialize(tx *Transaction, buf *bytes.Buffer)
	Deserialize(tx *Transaction, buf *bytes.Buffer)
}

type InvokeTransData struct {
	script []byte
	gas Fixed8
}

func (self *InvokeTransData) Serialize(tx *Transaction, buf *bytes.Buffer) {
	length := len(self.script)
	utils.WriteVarInt(buf, uint64(length))
	buf.Write(self.script)
	if tx.version >= 1 {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, self.gas.value)
		buf.Write(data)
	}
}

func (self *InvokeTransData) Deserialize(tx *Transaction, buf *bytes.Buffer) {
	length := utils.ReadVarInt(buf, 65535)
	data := make([]byte, length)
	buf.Read(data)
	self.script = data
	if tx.version >= 1 {
		value := make([]byte, 8)
		buf.Read(value)
		self.gas.value = binary.LittleEndian.Uint64(value)
	}
}

func (self *Witness)GetAddress() string  {
	hash := getScriptHashFromScript(self.VerificationScript)
	address, _ := getAddressFromScriptHash(hash)
	return address
}

func (self *Witness)GetHashStr() string  {
	hash := getScriptHashFromScript(self.VerificationScript)
	strHash := utils.ToHexString(hash)
	return strHash
}

func (self *Witness) IsSmartContract() bool  {
	if len(self.VerificationScript) != 35 {
		return true
	}
	if self.VerificationScript[0] != byte(len(self.VerificationScript) - 2) {
		return true
	}
	if self.VerificationScript[len(self.VerificationScript) - 1] != 0xac {
		return true
	}
	return false
}


type Transaction struct {
	txtype byte
	version byte
	attributes []Attribute
	inputs []TransactionInput
	outputs []TransactionOutput
	witnesses []Witness
	extdata IExtData
}

func (self *Transaction)GetMessage() ([]byte, bool)  {
	buf := &bytes.Buffer{}
	self.SerializeUnsigned(buf)

	return buf.Bytes(), true
}

func (self *Transaction)GetRawData() ([]byte, bool)  {
	buf := &bytes.Buffer{}
	self.Serialize(buf)
	return buf.Bytes(), true
}

func (self *Transaction)GetHash() ([]byte, bool)  {
	buf := &bytes.Buffer{}
	self.Serialize(buf)
	return buf.Bytes(), true
}

func (self *Transaction)AddWitness(signData []byte, pubkey *ecdsa.PublicKey, addrs string )  {
	buf := &bytes.Buffer{}
	self.SerializeUnsigned(buf)

	data := buf.Bytes()

	bSign := Verify(data, signData, pubkey)
	if !bSign {
		panic("runtime error: verify error")
	}

	addr := getAddressFromPublicKey(pubkey)
	if addr != addrs {
		panic("runtime error: address error")
	}

	vscript := getScriptFromPublicKey(pubkey)
	sb := &ScriptBuilder{}
	sb.EmitPushBytes(signData)

	iscript := sb.toBytes()
	self.AddWitnessScript(vscript, iscript)
}

func (self *Transaction)AddWitnessScript(script []byte, iscript []byte) bool {
	//scripthash := getScriptHashFromScript(script)
	newwit := Witness{}
	newwit.VerificationScript = script
	newwit.InvocationScript = iscript
	size := len(self.witnesses)
	for i := 0; i < size; i++ {
		tmpwit := self.witnesses[i]
		tmpAddr := tmpwit.GetAddress()
		newAddr := newwit.GetAddress()
		if tmpAddr == newAddr {
			return false
		}
	}
	self.witnesses = append(self.witnesses, newwit)
	return true
}

func (self *Transaction)SerializeUnsigned(buf *bytes.Buffer)  {
	buf.WriteByte(uint8(self.txtype))
	buf.WriteByte(self.version)
	if self.txtype == ContractTransaction {

	} else if self.txtype == InvocationTransaction {
		self.extdata.Serialize(self, buf)
	} else {
		panic("runtime error: tx type error")
	}

	length := len(self.attributes)
	utils.WriteVarInt(buf, uint64(length))

	for i := 0; i < length; i++ {
		attriData := self.attributes[i].data
		usage := self.attributes[i].usage

		if usage == ContractHash || usage == Vote || (usage >= Hash1 && usage <= Hash15) {
			buf.Write(attriData[0:32])
		} else if usage == ECDH02 || usage == ECDH03 {
			buf.Write(attriData[1:33])
		} else if usage == Script {
			buf.Write(attriData[0:20])
		} else if usage == DescriptionUrl {
			size := len(attriData)
			buf.WriteByte(uint8(size))
			buf.Write(attriData[0:size])
		} else if usage == Description || usage >= Remark {
			size := len(attriData)
			utils.WriteVarInt(buf, uint64(size))
			buf.Write(attriData[0:size])
		} else {
			panic("runtime error: attribute type error")
		}
	}

	countInputs := len(self.inputs)
	utils.WriteVarInt(buf, uint64(countInputs))
	for i := 0; i < countInputs; i++ {
		input := self.inputs[i]
		buf.Write(input.hash)

		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, uint16(input.index))
		buf.Write(data)
	}

	countOutputs := len(self.outputs)
	utils.WriteVarInt(buf, uint64(countOutputs))
	for i := 0; i < countOutputs; i++ {
		output := self.outputs[i]
		buf.Write(output.assetId)
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(output.value.value))
		buf.Write(data)
		buf.Write(output.toAddress)
	}
}

func (self *Transaction)Serialize(buf *bytes.Buffer)  {
	self.SerializeUnsigned(buf)

	length := len(self.witnesses)
	utils.WriteVarInt(buf, uint64(length))

	for i := 0; i < length; i++ {
		_witness := self.witnesses[i]
		utils.WriteVarInt(buf, uint64(len(_witness.InvocationScript)))
		buf.Write(_witness.InvocationScript)
		utils.WriteVarInt(buf, uint64(len(_witness.VerificationScript)))
		buf.Write(_witness.VerificationScript)
	}
}

func (self *Transaction)Deserialize(buf *bytes.Buffer)  {
	txtype, _ := buf.ReadByte()
	self.txtype = uint8(txtype)
	version, _ := buf.ReadByte()
	self.version = uint8(version)

	if txtype == ContractTransaction {
		self.extdata = nil
	} else if txtype == InvocationTransaction {
		self.extdata = &InvokeTransData{}
	} else {
		panic("runtime error: tx type error")
	}
	if self.extdata != nil {
		self.extdata.Deserialize(self, buf)
	}

	countAttri := utils.ReadVarInt(buf, 65535)
	if countAttri > 0 {
		self.attributes = make([]Attribute, countAttri)
	}
	var i uint64 = 0;
	for ; i < countAttri; i++ {
		usage, _ := buf.ReadByte()
		self.attributes[i].usage = usage

		if usage == ContractHash || usage == Vote || (usage >= Hash1 && usage <= Hash15) {
			attriData := make([]byte, 32)
			buf.Read(attriData)
			self.attributes[i].data = attriData
		} else if usage == ECDH02 || usage == ECDH03 {
			attriData := make([]byte, 33)
			attriData[0] = usage
			buf.Read(attriData[1:])
			self.attributes[i].data = attriData
		} else if usage == Script {
			attriData := make([]byte, 20)
			buf.Read(attriData)
			self.attributes[i].data = attriData
		} else if usage == DescriptionUrl {
			length, _ := buf.ReadByte()
			attriData := make([]byte, length)
			buf.Read(attriData)
			self.attributes[i].data = attriData

		} else if usage == Description || usage >= Remark {
			length := utils.ReadVarInt(buf, 65535)
			attriData := make([]byte, length)
			buf.Read(attriData)
			self.attributes[i].data = attriData
		} else {
			panic("runtime error: attribute type error")
		}
	}

	countInputs := utils.ReadVarInt(buf, 65535)
	if countInputs > 0 {
		self.inputs = make([]TransactionInput, countInputs)
	}
	i = 0
	for ; i < countInputs; i++ {
		hash := make([]byte, 32)
		buf.Read(hash)
		self.inputs[i].hash = hash

		indexBytes := make([]byte, 2)
		buf.Read(indexBytes)
		self.inputs[i].index = binary.LittleEndian.Uint16(indexBytes)
	}

	countOutputs := utils.ReadVarInt(buf, 65535)
	if countOutputs > 0 {
		self.outputs = make([]TransactionOutput, countOutputs)
	}
	i = 0
	for ; i < countOutputs; i++ {
		assetId := make([]byte, 32)
		buf.Read(assetId)
		self.outputs[i].assetId = assetId
		valueBytes := make([]byte, 8)
		buf.Read(valueBytes)
		self.outputs[i].value.value = binary.LittleEndian.Uint64(valueBytes)
		toAddress := make([]byte, 20)
		self.outputs[i].toAddress = toAddress
	}
}

type Utxo struct {
	Hash string
	Value uint64
	N uint16
}

type CreateSignParams struct {
	TxType byte
	Version byte
	PriKey string
	From string
	To string
	AssetId string
	Value uint64
	Data []byte
	Utxos []Utxo
}

func CreateContractTransaction(params *CreateSignParams) (string, bool) {
	tx := &Transaction{}
	tx.txtype = ContractTransaction
	tx.version = params.Version

	var sum uint64 = 0
	size := len(params.Utxos)
	if size > 0 {
		tx.inputs = make([]TransactionInput, size)
	}
	for i := 0; i < size; i++ {
		tx.inputs[i].hash, _ = utils.ToBytes(params.Utxos[i].Hash)
		tx.inputs[i].index = params.Utxos[i].N
		sum += params.Utxos[i].Value
	}

	value := params.Value
	toAddress := params.From
	if sum < value {
		return "", false
	}
	assetId := params.AssetId
	output := TransactionOutput{}
	vAssetId, _ := utils.ToBytes(assetId)
	vAssetId = utils.BytesReverse(vAssetId)
	output.assetId = vAssetId
	output.value.value = value
	pubkeyhash, _ := getPublicKeyHashFromAddress(toAddress)
	output.toAddress = pubkeyhash
	tx.outputs = append(tx.outputs, output)

	fromAddress := params.From
	left := sum - value
	if left > 0 {
		output2 := TransactionOutput{}
		output2.assetId = vAssetId
		output2.value.value = left
		pkh, _ := getPublicKeyHashFromAddress(fromAddress)
		output2.toAddress = pkh
		tx.outputs = append(tx.outputs, output)
	}

	unsignedData, _ := tx.GetMessage()
	privKey := &ecdsa.PrivateKey{}
	FromWIF(privKey, params.PriKey)

	signature, err := Sign(unsignedData, privKey)
	if err != nil {
		return "", false
	}

	pubKey := privKey.PublicKey
	tx.AddWitness(signature, &pubKey, fromAddress)

	rawData, _ := tx.GetRawData()
	raw := utils.ToHexString(rawData)

	return raw, true
}

func GetNep5Transfer(scriptAddress string, from, to string, num big.Int) ([]byte, bool) {
	sb := &ScriptBuilder{}
	assetId, _ := utils.ToBytes(scriptAddress)
	assetId = utils.BytesReverse(assetId)

	jsonData := make(map[string]interface{})

	fromParam := "(address)" + from;
	jsonData["from"] = fromParam

	toParam := "(address)" + to;
	jsonData["to"] = toParam

	strInt := num.String()
	numParam := "(integer)" + strInt
	jsonData["num"] = numParam

	paramList := &simplejson.Json{Data:jsonData}

	sb.EmitParamJson(paramList)
	sb.EmitPushString("transfer")
	sb.EmitAppCall(assetId, false)

	rawdata := sb.toBytes()
	return rawdata, true
}

func CreateInvocationTransaction(params *CreateSignParams) (string, bool) {
	tx := &Transaction{}
	tx.txtype = InvocationTransaction
	tx.version = params.Version

	var sum uint64 = 0
	size := len(params.Utxos)
	if size > 0 {
		tx.inputs = make([]TransactionInput, size)
	}
	for i := 0; i < size; i++ {
		tx.inputs[i].hash, _ = utils.ToBytes(params.Utxos[i].Hash)
		tx.inputs[i].index = params.Utxos[i].N
		sum += params.Utxos[i].Value
	}

	toAddress := params.From
	if sum <= 0 {
		return "", false
	}
	assetId := params.AssetId
	output := TransactionOutput{}
	vAssetId, _ := utils.ToBytes(assetId)
	vAssetId = utils.BytesReverse(vAssetId)
	output.assetId = vAssetId
	output.value.value = sum
	pubkeyhash, _ := getPublicKeyHashFromAddress(toAddress)
	output.toAddress = pubkeyhash
	tx.outputs = append(tx.outputs, output)

	fromAddress := params.From
	extdata := &InvokeTransData{}
	extdata.script = params.Data
	extdata.gas.value = 100000000;
	tx.extdata = extdata

	unsignedData, _ := tx.GetMessage()
	privKey := &ecdsa.PrivateKey{}
	FromWIF(privKey, params.PriKey)

	signature, err := Sign(unsignedData, privKey)
	if err != nil {
		return "", false
	}

	pubKey := privKey.PublicKey
	tx.AddWitness(signature, &pubKey, fromAddress)

	rawData, _ := tx.GetRawData()
	raw := utils.ToHexString(rawData)

	return raw, true
}