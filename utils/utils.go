package utils

import (
	"bytes"
	"encoding/hex"
	"encoding/binary"
)

func WriteUint16(buf *bytes.Buffer, value uint16)  {
	buf.WriteByte(byte(value))
	buf.WriteByte(byte(value >> 8))
}

func WriteUint32(buf *bytes.Buffer, value uint32)  {
	buf.WriteByte(byte(value))
	buf.WriteByte(byte(value >> 8))
	buf.WriteByte(byte(value >> 16))
	buf.WriteByte(byte(value >> 24))
}

func WriteUint64(buf *bytes.Buffer, value uint64)  {
	buf.WriteByte(byte(value))
	buf.WriteByte(byte(value >> 8))
	buf.WriteByte(byte(value >> 16))
	buf.WriteByte(byte(value >> 24))
	buf.WriteByte(byte(value >> 32))
	buf.WriteByte(byte(value >> 40))
	buf.WriteByte(byte(value >> 48))
	buf.WriteByte(byte(value >> 56))
}

func BytesReverse(bytes []byte) []byte  {
	ret := make([]byte, len(bytes))
	copy(ret, bytes)
	for i, j := 0, len(ret) - 1; i < j; i, j = i + 1, j - 1 {
		ret[i], ret[j] = ret[j], ret[i]
	}
	return ret
}

func Substr(str string, start, length int) string {
	rs := []rune(str)
	rl := len(rs)
	end := 0

	if start < 0 {
		start = rl - 1 + start
	}
	end = start + length

	if start > end {
		start, end = end, start
	}

	if start < 0 {
		start = 0
	}
	if start > rl {
		start = rl
	}
	if end < 0 {
		end = 0
	}
	if end > rl {
		end = rl
	}
	return string(rs[start:end])
}

func ToHexString(data []byte) (string) {
	str := hex.EncodeToString(data)
	return str
}

func ToBytes(strHex string) ([]byte, bool) {
	data, err := hex.DecodeString(strHex)
	if err != nil {
		return nil, false
	}

	return data, true
}

func WriteVarInt(buf *bytes.Buffer, value uint64 )  {
	if value > 0xffffffff {
		buf.WriteByte(byte(0xff))

		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, value)
		buf.Write(data)
	} else if value > 0xffff {
		buf.WriteByte(byte(0xfe))

		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, uint32(value))
		buf.Write(data)
	} else if value > 0xfc {
		buf.WriteByte(byte(0xfd))

		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, uint16(value))
		buf.Write(data)
	} else {
		buf.WriteByte(uint8(value))
	}
}

func ReadVarInt(buf *bytes.Buffer, max uint64) uint64 {
	fb, _ := buf.ReadByte()
	var value uint64 = 0

	if fb == 0xfd {
		data := make([]byte, 2)
		buf.Read(data)

		value = uint64(binary.LittleEndian.Uint16(data))
	} else if fb == 0xfe {
		data := make([]byte, 4)
		buf.Read(data)

		value = uint64(binary.LittleEndian.Uint32(data))
	} else if fb == 0xff {
		data := make([]byte, 8)
		buf.Read(data)

		value = binary.LittleEndian.Uint64(data)
	} else {
		value = uint64(fb)
	}

	return value
}