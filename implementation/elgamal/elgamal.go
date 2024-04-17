package elgamal

import (
	"AAA/curve25519"
	"crypto/cipher"
	"errors"
	"log"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/random"
)

func NewKeyPair(suite *curve25519.SuiteCurve25519, random cipher.Stream) (kyber.Scalar, kyber.Point) {
	x := suite.Scalar().Pick(random)
	X := suite.Point().Mul(x, nil)
	return x, X
}

// M = C1-C2*sk
func Decrypt(suite suites.Suite, a []byte, cipherText []byte, secret kyber.Scalar) ([]byte, error) {
	// rP := new(curve25519.ProjPoint)
	log.Println()
	log.Println("***************************Decryption****************************")
	log.Println()
	rP := suite.Point()
	err := rP.UnmarshalBinary(a)
	if err != nil {
		return nil, err
	}
	srP := suite.Point().Mul(secret, rP).(*curve25519.ProjPoint)
	//  normalize
	srP.MarshalBinary()
	return recovery(suite, srP, cipherText)
}
func recovery(suite suites.Suite, srP kyber.Point, cipherText []byte) ([]byte, error) {
	c1 := suite.Point()
	err := c1.UnmarshalBinary(cipherText)
	if err != nil {
		return nil, err
	}
	c1.Sub(c1, srP)
	return c1.(*curve25519.ProjPoint).PointToMsg()

}
func Encrypt(suite suites.Suite, publicKey kyber.Point, msg []byte) ([]byte, []byte, error) {

	// log.Println("***************************Encryption****************************")

	r := suite.Scalar().Pick(random.New())
	c2 := suite.Point().Mul(r, nil)
	rPubKey := suite.Point().Mul(r, publicKey)
	mPoint := suite.Point().Base().(*curve25519.ProjPoint)
	mPoint.MsgToPoint(msg)

	c1 := suite.Point().Add(mPoint, rPubKey)
	byte1, _ := c1.MarshalBinary()
	byte2, _ := c2.MarshalBinary()
	return byte1, byte2, nil

}

type KeyPair struct {
	X         int
	SecretKey kyber.Scalar
	PublicKey kyber.Point
}

func GenerateKeyPair(suite suites.Suite, t int, n int, masterSecretKey kyber.Scalar) []KeyPair {
	var result = make([]KeyPair, n)
	var params = make([]kyber.Scalar, t)
	params[0] = masterSecretKey
	// f(x) = params[0] + params[1]*x + ... + params[t-1]*x^{t-1}
	for i := 1; i < t; i++ {
		// params[i] = suite.G2().Scalar().Pick(random.New())
		params[i] = suite.Scalar().Clone().SetInt64(int64(i))

	}
	// generate n secret key
	// compute f(1), f(2), ..., f(n)
	for i := 1; i <= n; i++ {
		x := suite.Scalar().SetInt64(int64(i))
		secretKey := params[0].Clone()
		for j := 1; j < t; j++ {
			a1 := exp(suite, x, j)
			a2 := suite.Scalar().Mul(params[j], a1)
			secretKey = secretKey.Add(secretKey, a2)
			secretKey = secretKey.Add(secretKey, suite.Scalar().Mul(params[j], exp(suite, x, j)))
		}
		key := KeyPair{X: i, SecretKey: secretKey, PublicKey: suite.Point().Mul(secretKey, suite.Point().Base())}
		// x.(*mod.Int).M.Int64()
		result[i-1] = key
	}
	//X := suite.G2().Point().Mul(x, nil)
	return result
}

func Exp(a kyber.Scalar, e *big.Int) kyber.Scalar {
	ai := a.(*mod.Int)
	result := ai.Exp(a, e)
	return result
}

func exp(suite suites.Suite, base kyber.Scalar, n int) kyber.Scalar {
	// Int()
	if n == 0 {
		return suite.Scalar().One()
	}
	if n == 1 {
		return base
	}
	result := base.Clone()
	for i := 2; i <= n; i++ {
		result = suite.Scalar().Mul(result, base)
	}
	return result
}

func Aggre(suite suites.Suite, sRP []kyber.Point, x []int) (kyber.Point, error) {
	signLength := len(sRP)
	xLength := len(x)
	if signLength != xLength {
		return nil, errors.New("the length of signatures doesn't match the length of x")
	}
	var rP kyber.Point
	for i := 0; i < signLength; i++ {
		index, error := geneIndex(suite, x, i)
		if error != nil {
			return nil, error
		}
		item := suite.Point().Mul(index, sRP[i])
		if rP == nil {
			rP = item
		} else {
			rP = suite.Point().Add(rP, item)
		}
	}
	rP.MarshalBinary()
	return rP, nil
}

func ThresholdDecrypt(suite suites.Suite, sRP []kyber.Point, x []int, cipherText []byte) ([]byte, error) {
	rP, err := Aggre(suite, sRP, x)
	if err != nil {
		return nil, err
	}
	rP.MarshalBinary()
	return recovery(suite, rP, cipherText)

}

func geneIndex(suite suites.Suite, x []int, i int) (kyber.Scalar, error) {
	if i < 0 || i > len(x)-1 {
		return nil, errors.New("i exceeds the allowed index")
	}
	// Scalar := suite.G2().Scalar()
	result := suite.Scalar().One().Clone()
	length := len(x)
	scalarX := make([]kyber.Scalar, length)
	for index, value := range x {
		// fmt.Println(value, "   ", index)
		scalarX[index] = suite.Scalar().SetInt64(int64(value))
	}
	for j := 0; j < length; j++ {
		if j != i {
			t := suite.Scalar().Div(scalarX[j], suite.Scalar().Sub(scalarX[j], scalarX[i]))
			result = suite.Scalar().Mul(t, result)
		}
	}
	return result, nil

}

func Deal(suite suites.Suite, rp []byte, subSecretKey kyber.Scalar) (kyber.Point, error) {
	rP := suite.Point().Base()
	err := rP.UnmarshalBinary(rp)
	if err != nil {
		return nil, err
	}
	p := suite.Point().Mul(subSecretKey, rP)
	return p, nil
}
