package Neo

import (
	"bytes"
	"math/big"
	"github.com/neo-thinsdk-go/OpCode"
	"github.com/neo-thinsdk-go/utils"
	"github.com/neo-thinsdk-go/simplejson"
	"strings"
)

type ScriptBuilder struct {
	buf bytes.Buffer
}

func (sb *ScriptBuilder) toBytes() []byte {
	return sb.buf.Bytes()
}

func (sb *ScriptBuilder) Emit(opcode byte, arg []byte)   {
	sb.buf.WriteByte(opcode)
	if len(arg) != 0 {
		sb.buf.Write(arg)
	}
}

func (sb *ScriptBuilder) EmitAppCall(scriptHash []byte, useTailCall bool)  {
	if len(scriptHash) != 20 {
		panic("runtime error: script hash length error")
	}

	opcode := OpCode.TAILCALL
	if !useTailCall {
		opcode = OpCode.APPCALL
	}
	sb.Emit(opcode, scriptHash)
}

func (sb *ScriptBuilder) EmitJump(opcode byte, offset int16) {
	if opcode != OpCode.JMP && opcode != OpCode.JMPIF && opcode != OpCode.JMPIFNOT && opcode != OpCode.CALL {
		panic("runtime error: opcode error")
	}
	var buf bytes.Buffer
	utils.WriteUint16(&buf, uint16(offset))
	sb.Emit(opcode, buf.Bytes())
}

func (sb *ScriptBuilder) EmitPushNumber(number big.Int)  {
	var minusOne = big.NewInt(-1)
	if number.Cmp(minusOne) == 0 {
		sb.Emit(OpCode.PUSHM1, []byte{})
		return
	}
	var zero = big.NewInt(0)
	if number.Cmp(zero) == 0 {
		sb.Emit(OpCode.PUSH0, []byte{})
		return
	}

	var sixteen = big.NewInt(16)
	if number.Cmp(zero) == 1 && number.Cmp(sixteen) == -1 {
		opcode := OpCode.PUSH1 - 1 + (uint8)(number.Uint64())
		sb.Emit(opcode, []byte{})
		return
	}

	sb.EmitPushBytes(number.Bytes())
}

func (sb *ScriptBuilder) EmitPushBool(b bool)  {
	if b {
		sb.Emit(OpCode.PUSHT, []byte{})
	} else {
		sb.Emit(OpCode.PUSHF, []byte{})
	}
}

func (sb *ScriptBuilder) EmitPushBytes(bytes []byte)  {
	length := len(bytes)
	if length <= int(OpCode.PUSHBYTES75) {
		sb.buf.WriteByte(byte(length))
		sb.buf.Write(bytes)
	} else if length < 0x100 {
		sb.Emit(OpCode.PUSHDATA1, []byte{})
		sb.buf.WriteByte(byte(length))
		sb.buf.Write(bytes)
	} else if length < 0x10000 {
		sb.Emit(OpCode.PUSHDATA2, []byte{})
		utils.WriteUint16(&sb.buf, uint16(length))
		sb.buf.Write(bytes)
	} else {
		sb.Emit(OpCode.PUSHDATA4, []byte{})
		utils.WriteUint32(&sb.buf, uint32(length))
		sb.buf.Write(bytes)
	}
}

func (sb *ScriptBuilder) EmitPushString(data string)  {
	sb.EmitPushBytes([]byte(data))
}

func (sb *ScriptBuilder) EmitSysCall(api string)  {
	hexdata := []byte(api)
	length := len(hexdata)
	if length <= 0 || length > 252 {
		panic("runtime error: api length error")
	}

	var buf bytes.Buffer
	buf.WriteByte(uint8(length))
	buf.Write(hexdata)
	sb.Emit(OpCode.SYSCALL, buf.Bytes())
 }

func getParamBytes(buf * bytes.Buffer, str string) bool {
	bytes := []byte(str)
	if bytes[0] != '(' {
		return false
	}
	length := len(bytes)

	if strings.Index(str, "(str)") == 0 {
		strData := utils.Substr(str, 5, length - 5)
		buf.Write([]byte(strData))
	} else if strings.Index(str, "(string)") == 0 {
		strData := utils.Substr(str, 8, length - 8)
		buf.Write([]byte(strData))
	} else if strings.Index(str, "(bytes)") == 0 {
		strData := utils.Substr(str, 7, length - 7)
		data, _ := utils.ToBytes(strData)
		buf.Write(data)
	} else if strings.Index(str, "([])") == 0 {
		strData := utils.Substr(str, 4, length - 4)
		data, _ := utils.ToBytes(strData)
		buf.Write(data)
	} else if strings.Index(str, "(address)") == 0 {
		strData := utils.Substr(str, 9, length - 9)
		pubHash, _ := getPublicKeyHashFromAddress(strData)
		buf.Write(pubHash)
	} else if strings.Index(str, "(addr)") == 0 {
		strData := utils.Substr(str, 6, length - 6)
		pubHash, _ := getPublicKeyHashFromAddress(strData)
		buf.Write(pubHash)
	} else if strings.Index(str, "(integer)") == 0 {
		strData := utils.Substr(str, 9, length - 9)
		value := &big.Int{}
		value, _ = value.SetString(strData, 10)
		data := value.Bytes()
		buf.Write(data)
	} else if strings.Index(str, "(int)") == 0 {
		strData := utils.Substr(str, 5, length - 5)
		value := &big.Int{}
		value, _ = value.SetString(strData, 10)
		data := value.Bytes()
		buf.Write(data)

	} else if strings.Index(str, "(hexinteger)") == 0 {
		strData := utils.Substr(str, 12, length - 12)
		data, _ := utils.ToBytes(strData)
		buf.Write(data)

	} else if strings.Index(str, "(hexint)") == 0 {
		strData := utils.Substr(str, 8, length - 8)
		data, _ := utils.ToBytes(strData)
		buf.Write(data)
	} else if strings.Index(str, "(hex)") == 0 {
		strData := utils.Substr(str, 5, length - 5)
		data, _ := utils.ToBytes(strData)
		buf.Write(data)
	} else if strings.Index(str, "(hex256)") == 0 || strings.Index(str, "(int256)") == 0 {
		strData := utils.Substr(str, 8, length - 8)
		data, _ := utils.ToBytes(strData)
		if len(data) != 32 {
			return false
		}
		buf.Write(data)

	} else if strings.Index(str, "(uint256)") == 0 {
		strData := utils.Substr(str, 9, length - 9)
		data, _ := utils.ToBytes(strData)
		if len(data) != 32 {
			return false
		}
		buf.Write(data)
	} else if strings.Index(str, "(hex160)") == 0 || strings.Index(str,"(int160)" ) == 0 {
		strData := utils.Substr(str, 8, length - 8)
		data, _ := utils.ToBytes(strData)
		if len(data) != 20 {
			return false
		}
		buf.Write(data)
	} else if strings.Index(str, "(uint160)") == 0 {
		strData := utils.Substr(str, 9, length - 9)
		data, _ := utils.ToBytes(strData)
		if len(data) != 20 {
			return false
		}
		buf.Write(data)
	} else {
		return false
	}

	return true
}

func (sb *ScriptBuilder) pushParam(param interface{}) {
	switch v := param.(type) {
	case bool:
		sb.EmitPushBool(v)
	case int:
		var value = big.NewInt(int64(v))
		sb.EmitPushNumber(*value)
	case int64:
		var value = big.NewInt(v)
		sb.EmitPushNumber(*value)
	case []interface{}:
		length := len(v)
		for i := length - 1; i >= 0; i-- {
			sb.pushParam(v[i])
		}
	case map[string]interface{}:
		for _, value := range v {
			sb.pushParam(value)
		}
	case string:
		var buf bytes.Buffer
		getParamBytes(&buf, v)
		sb.EmitPushBytes(buf.Bytes())
	default:
		panic("runtime error: data type error")
	}
}

func (sb *ScriptBuilder) EmitParamJson(param *simplejson.Json)  {
	sb.pushParam(param.Data)
}