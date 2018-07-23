package Neo

import (
	"math/big"
	"crypto/ecdsa"
	"bytes"
	"fmt"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/ripemd160"
)

type Point struct {
	X *big.Int
	Y *big.Int
}


// ToBytes converts a Bitcoin private key to a 32-byte byte slice.
func PrivateToBytes(priv *ecdsa.PrivateKey) (b []byte)  {
	d := priv.D.Bytes()
	/* Pad D to 32 bytes */
	padded_d := append(bytes.Repeat([]byte{0x00}, 32-len(d)), d...)

	return padded_d
}


// FromBytes converts a 32-byte byte slice to a Bitcoin private key and derives the corresponding Bitcoin public key.
func PrivateFromBytes(priv *ecdsa.PrivateKey, b []byte) (err error) {
	if len(b) != 32 {
		return fmt.Errorf("Invalid private key bytes length %d, expected 32.", len(b))
	}

	priv.D = new(big.Int).SetBytes(b)

	/* Derive public key from private key */
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(priv.D.Bytes())

	return nil
}

func PrivateToWIF(priv *ecdsa.PrivateKey) (wif string) {
	/*
	priv_bytes := PrivateToBytes(priv)
	priv_bytes = append(priv_bytes, NEO_PRIVATE_SENTINEL)
	wif = b58checkencode(NEO_PRIVATE_VERSION, priv_bytes)
	*/

	priv_bytes := make([]byte, 33)
	d := priv.D.Bytes()
	copy(priv_bytes[0:32], d)
	priv_bytes[32] = 0x01
	wif = b58checkencode(NEO_PRIVATE_VERSION, priv_bytes)

	return wif
}

// FromWIF converts a Wallet Import Format string to a Bitcoin private key and derives the corresponding Bitcoin public key.
func FromWIF(priv *ecdsa.PrivateKey, wif string) (err error) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	/* Base58 Check Decode the WIF string */
	ver, priv_bytes, err := b58checkdecode(wif)
	if err != nil {
		return err
	}

	/* Check that the version byte is 0x80 */
	if ver != 0x80 {
		return fmt.Errorf("Invalid WIF version 0x%02x, expected 0x80.", ver)
	}

	/* If the private key bytes length is 33, check that suffix byte is 0x01 (for compression) and strip it off */
	if len(priv_bytes) == 33 {
		if priv_bytes[len(priv_bytes)-1] != 0x01 {
			return fmt.Errorf("Invalid private key, unknown suffix byte 0x%02x.", priv_bytes[len(priv_bytes)-1])
		}
		priv_bytes = priv_bytes[0:32]
	}

	/* Convert from bytes to a private key */
	err = PrivateFromBytes(priv, priv_bytes)
	if err != nil {
		return err
	}

	return nil
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	x, y := new(big.Int),new(big.Int)
	if len(pubkey) != 33 {
		return nil, fmt.Errorf("invalid public key")
	}
	if (pubkey[0] != 0x02) && (pubkey[0] != 0x03) {
		return nil, fmt.Errorf("invalid public key")
	}
	if x == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	x.SetBytes(pubkey[1:])

	xxx := new(big.Int).Mul(x,x)
	xxx.Mul(xxx,x)

	ax := new(big.Int).Mul(big.NewInt(3),x)

	yy := new(big.Int).Sub(xxx, ax)
	yy.Add(yy,elliptic.P256().Params().B)

	y1 := new(big.Int).ModSqrt(yy,elliptic.P256().Params().P)
	if y1 == nil {
		return nil, fmt.Errorf("can not revcovery public key")
	}

	y2 := new(big.Int).Neg(y1)
	y2.Mod(y2,elliptic.P256().Params().P)

	if pubkey[0] == 0x02 {
		if y1.Bit(0) == 0 {
			y = y1
		} else {
			y = y2
		}
	} else {
		if y1.Bit(0) == 1 {
			y = y1
		} else {
			y = y2
		}
	}
	//fmt.Println("dx:",x)
	//fmt.Println("dy:",y)
	return &ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()}, nil
}

// CompressPubkey encodes a public key to the 33-byte compressed format.
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	//fmt.Println("cx:",pubkey.X)
	//fmt.Println("cy:",pubkey.Y)
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	/*
	params := pubkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	xBytes := pubkey.X.Bytes()
	signature := make([]byte, curveOrderByteSize+1)
	if pubkey.Y.Bit(0) == 1 {
		signature[0] = 0x03
	} else {
		signature[0] = 0x02
	}
	copy(signature[1+curveOrderByteSize-len(xBytes):], xBytes)
	return signature
	*/
	data := make([]byte, 33)
	if pubkey.Y.Bit(0) == 0 {
		data[0] = 0x02
	} else {
		data[0] = 0x03
	}
	copy(data[1:], pubkey.X.Bytes())
	return data
}

func PublicToAddress(pubkey *ecdsa.PublicKey) (address string)  {
	return getAddressFromPublicKey(pubkey)
}

func getScriptFromPublicKey(pubkey *ecdsa.PublicKey) ( []byte)  {
	script := make([]byte, 35, 35)
	script[0] = 33
	pubbytes := CompressPubkey(pubkey)
	copy(script[1:], pubbytes)
	script[34] =172

	return script
}

func getScriptHashFromScript(script []byte) ([]byte) {
	sha256_h := sha256.New()
	sha256_h.Reset()
	sha256_h.Write(script)
	pub_hash_1 := sha256_h.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160_h := ripemd160.New()
	ripemd160_h.Reset()
	ripemd160_h.Write(pub_hash_1)
	pub_hash_2 := ripemd160_h.Sum(nil)

	return pub_hash_2
}

func getAddressFromScriptHash(scriptHash []byte) (string, bool) {
	length := len(scriptHash)
	if length != 20 {
		return "", false
	}

	address := b58checkencode(NEO_ADDRESS_VERSION, scriptHash)
	return address, true
}

func getAddressFromPublicKey(pubkey *ecdsa.PublicKey) string {
	script := getScriptFromPublicKey(pubkey)
	scriptHash := getScriptHashFromScript(script)
	address, _ := getAddressFromScriptHash(scriptHash)
	return address
}

func getPublicKeyHashFromAddress(address string) ([]byte, bool) {
	ver, bytes, err := b58checkdecode(address)
	if err != nil {
		return nil, false
	}

	if ver != NEO_ADDRESS_VERSION {
		return nil, false
	}

	if len(bytes) != (int)(SCRIPT_HASH_LENGTH) {
		return nil, false
	}

	return bytes, true
}