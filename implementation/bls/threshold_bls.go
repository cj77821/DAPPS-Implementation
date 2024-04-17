package bls

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

type KeyPair struct {
	x         int
	secretKey kyber.Scalar
	publicKey kyber.Point
}

// ************************** (t,n)-threshold BLS **********************************//
func generateKeyPair(suite pairing.Suite, t int, n int, masterSecretKey kyber.Scalar) []KeyPair {
	var result = make([]KeyPair, n)
	var params = make([]kyber.Scalar, t)
	params[0] = masterSecretKey
	// f(x) = params[0] + params[1]*x + ... + params[t-1]*x^{t-1}
	for i := 1; i < t; i++ {
		// params[i] = suite.G2().Scalar().Pick(random.New())
		params[i] = suite.G2().Scalar().Clone().SetInt64(int64(i))

	}
	// generate n secret key
	// compute f(1), f(2), ..., f(n)
	for i := 1; i <= n; i++ {
		x := suite.G2().Scalar().SetInt64(int64(i))
		secretKey := params[0].Clone()
		for j := 1; j < t; j++ {
			a1 := exp(suite, x, j)
			a2 := suite.G2().Scalar().Mul(params[j], a1)
			secretKey = secretKey.Add(secretKey, a2)
			secretKey = secretKey.Add(secretKey, suite.G2().Scalar().Mul(params[j], exp(suite, x, j)))
		}
		key := KeyPair{x: i, secretKey: secretKey, publicKey: suite.G2().Point().Mul(secretKey, suite.G2().Point().Base())}
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

func exp(suite pairing.Suite, base kyber.Scalar, n int) kyber.Scalar {
	// Int()
	if n == 0 {
		return suite.G2().Scalar().One()
	}
	if n == 1 {
		return base
	}
	result := base.Clone()
	for i := 2; i <= n; i++ {
		result = suite.G2().Scalar().Mul(result, base)
	}
	return result
}

func aggre(suite pairing.Suite, sigs [][]byte, x []int, t int, n int) ([]byte, error) {
	signLength := len(sigs)
	if signLength != len(x) {
		return nil, errors.New("the length of signatures doesn't match the length of x")
	}
	result := suite.G1().Point()
	for i := 0; i < signLength; i++ {
		sigToAdd := suite.G1().Point()
		sigToAdd.UnmarshalBinary(sigs[i])
		index, error := geneIndex(suite, x, i)
		if error != nil {
			return nil, error
		}
		item := suite.G1().Point().Mul(index, sigToAdd)
		result = suite.G1().Point().Add(result, item)
	}
	s, err := result.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func geneIndex(suite pairing.Suite, x []int, i int) (kyber.Scalar, error) {
	if i < 0 || i > len(x)-1 {
		return nil, errors.New("i exceeds the allowed index")
	}
	// Scalar := suite.G2().Scalar()
	result := suite.G2().Scalar().One().Clone()
	length := len(x)
	scalarX := make([]kyber.Scalar, length)
	for index, value := range x {
		// fmt.Println(value, "   ", index)
		scalarX[index] = suite.G2().Scalar().SetInt64(int64(value))
	}
	for j := 0; j < length; j++ {
		if j != i {
			t := suite.G2().Scalar().Div(scalarX[j], suite.G2().Scalar().Sub(scalarX[j], scalarX[i]))
			result = suite.G2().Scalar().Mul(t, result)
		}
	}
	return result, nil

}

// func compressPoint(sign []byte) {
// 	if len(sign) != 64 {

// 	}
// }

func ThresholdBLS(t int, n int) error {
	start := time.Now()
	suite := bn256.NewSuite()
	// fmt.Println(suite.G1().Point().Base().String())
	// fmt.Println(suite.G2().Point().Base().String())

	// fmt.Println(suite.GT().Point().Base().String())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")

	masterSecretKey, masterPublicKey := NewKeyPair(suite, random.New())
	// fmt.Println(masterPublicKey)
	// masterSecretKey1 := suite.G2().Scalar().SetInt64(2)
	// masterPublicKey1 := suite.G2().Point().Mul(masterSecretKey1, nil)
	// x := suite.G2().Scalar().Pick(random)
	// X := suite.G2().Point().Mul(x, nil)
	keyPairs := generateKeyPair(suite, t, n, masterSecretKey)

	var signs [][]byte
	for i := 0; i < t; i++ {
		subSign, error := Sign(suite, keyPairs[i].secretKey, msg)
		if error != nil {
			return error
		}
		// r := Verify(suite, keyPairs[1].publicKey, msg, subSign)
		// if error != nil {
		// 	fmt.Println(error)
		// 	return
		// }
		// fmt.Println(r)
		signs = append(signs, subSign)
	}
	start1 := time.Now()
	var signsTest [][]byte
	for i := 0; i < 100; i++ {
		for j := 0; j < t; j++ {
			subSign, error := Sign(suite, keyPairs[j].secretKey, msg)
			if error != nil {
				return error
			}
			// r := Verify(suite, keyPairs[1].publicKey, msg, subSign)
			// if error != nil {
			// 	fmt.Println(error)
			// 	return
			// }
			// fmt.Println(r)
			signsTest = append(signsTest, subSign)
		}

	}
	cost1 := time.Since(start1)
	fmt.Println("server cost:", cost1/100)

	var newSigns [][]byte
	for i := 0; i < t; i++ {
		err := bls.Verify(suite, keyPairs[i].publicKey, msg, signs[i])
		if err == nil {
			newSigns = append(newSigns, signs[i])
		}
		if len(newSigns) == t {
			break
		}

	}
	if len(newSigns) != t {
		return errors.New("there doesn't have enough signatures")
	}
	var newX []int
	for i := 0; i < t; i++ {
		// newSigns = append(newSigns, signs[i])
		newX = append(newX, keyPairs[i].x)
	}

	aggreSignature, error := aggre(suite, newSigns, newX, t, n)
	if error != nil {
		return error
	}
	// fmt.Println("the length of signature is:", len(aggreSignature))
	verificationError := Verify(suite, masterPublicKey, msg, aggreSignature)
	// if verificationError != nil {
	// 	return verificationError
	// } else {
	// 	fmt.Println("success")
	// }
	if verificationError != nil {
		fmt.Println("failed")
	} else {
		fmt.Println("success")
	}
	cost := time.Since(start)
	fmt.Println("time:", cost)

	total := time.Duration.Abs(0)
	for i := 0; i < 100; i++ {
		start := time.Now()
		var newSigns [][]byte
		for i := 0; i < t; i++ {
			err := bls.Verify(suite, keyPairs[i].publicKey, msg, signs[i])
			if err == nil {
				newSigns = append(newSigns, signs[i])
			}
			if len(newSigns) == t {
				break
			}

		}
		if len(newSigns) != t {
			return errors.New("There doesn't have enough signatures")
		}
		var newX []int
		for i := 0; i < t; i++ {
			// newSigns = append(newSigns, signs[i])
			newX = append(newX, keyPairs[i].x)
		}

		aggreSignature, error := aggre(suite, newSigns, newX, t, n)
		if error != nil {
			return error
		}
		// fmt.Println("the length of signature is:", len(aggreSignature))
		Verify(suite, masterPublicKey, msg, aggreSignature)
		// if verificationError != nil {
		// 	return verificationError
		// } else {
		// 	fmt.Println("success")
		// }
		cost := time.Since(start)
		total = total + cost
	}

	fmt.Println("user cost", total/100)

	return verificationError
	//Sign(suite, )
	// t := suite.G1().Scalar().One()
	// t = t.Add(t, t)
	// // t1 := exp(suite, t, 0)
	// // t2 := exp(suite, t, 1)
	// t3 := exp(suite, t, 4)
	// fmt.Println(t)
	// // fmt.Println(t1)
	// // fmt.Println(t2)
	// fmt.Println(t3)
}
