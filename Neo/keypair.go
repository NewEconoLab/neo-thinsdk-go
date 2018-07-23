package Neo

import (
	"crypto/elliptic"
	"math/big"
	"fmt"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/rand"
)
// NewSigningKey generates a random P-256 ECDSA private key.
func NewSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

// Sign signs arbitrary data using ECDSA.
func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	// hash message
	digest := sha256.Sum256(data)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	// encode the signature {R, S}
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	//privkey.PublicKey.Y

	return signature, nil
}

// Verify checks a raw ECDSA signature.
// Returns true if it's valid and false if not.
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	// hash message
	digest := sha256.Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}


func ecRecovery(data []byte, rawSign []byte) (*ecdsa.PublicKey,*ecdsa.PublicKey, error) {
	r := big.Int{}
	s := big.Int{}
	sigLen := len(rawSign)
	r.SetBytes(rawSign[:(sigLen / 2)])
	s.SetBytes(rawSign[(sigLen / 2):])

	expy := new(big.Int).Sub(elliptic.P256().Params().N,big.NewInt(2))
	rinv := new(big.Int).Exp(&r,expy ,elliptic.P256().Params().N)
	z := new(big.Int).SetBytes(data)

	xxx := new(big.Int).Mul(&r,&r)
	xxx.Mul(xxx,&r)

	ax := new(big.Int).Mul(big.NewInt(3),&r)

	yy := new(big.Int).Sub(xxx, ax)
	yy.Add(yy,elliptic.P256().Params().B)

	//y_squard := new(big.Int).Mod(tmp4,elliptic.P256().Params().P)

	y1 := new(big.Int).ModSqrt(yy,elliptic.P256().Params().P)
	if y1 == nil {
		return nil, nil, fmt.Errorf("can not revcovery public key")
	}

	y2 := new(big.Int).Neg(y1)
	y2.Mod(y2,elliptic.P256().Params().P)
	p1, p2 := elliptic.P256().ScalarMult(&r,y1,s.Bytes())
	p3, p4 := elliptic.P256().ScalarBaseMult(z.Bytes())

	p5 := new(big.Int).Neg(p4)
	p5.Mod(p5,elliptic.P256().Params().P)

	q1, q2 := elliptic.P256().Add(p1,p2,p3,p5)
	q3, q4 := elliptic.P256().ScalarMult(q1,q2,rinv.Bytes())

	n1, n2 := elliptic.P256().ScalarMult(&r,y2,s.Bytes())
	n3, n4 := elliptic.P256().ScalarBaseMult(z.Bytes())

	n5 := new(big.Int).Neg(n4)
	n5.Mod(n5,elliptic.P256().Params().P)

	q5, q6 := elliptic.P256().Add(n1,n2,n3,n5)
	q7, q8 := elliptic.P256().ScalarMult(q5,q6,rinv.Bytes())

	key1 := ecdsa.PublicKey{Curve:elliptic.P256(),X:q3,Y:q4}
	key2 := ecdsa.PublicKey{Curve:elliptic.P256(),X:q7,Y:q8}
	return &key1,&key2, nil
}

func comparePublicKey(key1, key2 *ecdsa.PublicKey) bool {
	x := key1.X.Cmp(key2.X)
	y := key2.Y.Cmp(key2.Y)
	if x == 0 && y == 0 {
		return true
	} else {
		return false
	}
}
/*
func testCompressPublicKey() {
	fmt.Println("--------------")
	key, err := NewSigningKey()
	if err != nil {
		log.Fatal(err)
	}
	compressed := CompressPubkey(&key.PublicKey)
	log.Println(compressed)
	uncompressed,err := DecompressPubkey(compressed)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(uncompressed)
	result := comparePublicKey(&key.PublicKey,uncompressed)
	if result != true {
		log.Fatal("result does not match!")
	}

}

func main() {

	testCompressPublicKey()
}

*/
