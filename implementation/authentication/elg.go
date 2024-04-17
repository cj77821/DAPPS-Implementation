package authentication

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
)

type PP struct {
	cpk1, cpk2, cpk3, apk kyber.Point
}
type Token struct {
	u1, u2, u3 kyber.Point
}

type BlindToken struct {
	a, b, c, d kyber.Point
	te         int64
	IDs        string
}

func (bt *BlindToken) GetPublic() kyber.Point {
	return bt.c
}

type Proof struct {
	v1, v2 kyber.Point
	v3, v4 kyber.Scalar
	tp     int64
}

func NewPP(cpk1 kyber.Point, cpk2 kyber.Point, cpk3 kyber.Point, apk kyber.Point) *PP {
	return &PP{
		cpk1: cpk1, cpk2: cpk2, cpk3: cpk3, apk: apk,
	}
}

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

// NewKeyPair creates a new BLS signing key pair. The private key x is a scalar
// and the public key X is a point on curve G2.
func NewKeyPair(suite pairing.Suite, random cipher.Stream) (kyber.Scalar, kyber.Point) {
	x := suite.G2().Scalar().Pick(random)
	X := suite.G2().Point().Mul(x, nil)
	return x, X
}

// Hash to G
func Hash2(suite pairing.Suite, msg []byte) (kyber.Point, error) {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement hashablePoint")
	}
	result := hashable.Hash(msg)
	return result, nil
}

// Hash to Zp
func Hash1(suite pairing.Suite, msg []byte) (kyber.Scalar, error) {
	hash := sha256.Sum256(msg)
	u1 := suite.G1().Scalar().SetBytes(hash[:])

	return u1, nil
}

func GenerateToken(suite pairing.Suite, te int64, Y kyber.Point, H kyber.Point, IDs string, csk1 kyber.Scalar, csk2 kyber.Scalar, csk3 kyber.Scalar, tsk kyber.Scalar) (*Token, error) {

	msg, ok := Y.MarshalBinary()
	if ok != nil {
		return nil, errors.New("msg1")
	}
	msg = append(msg, []byte(fmt.Sprintf("%d", te))...)
	u1, err := Hash2(suite, msg)
	if err != nil {
	}
	a := suite.G1().Point().Mul(csk1, u1)
	b := suite.G1().Point().Mul(csk2, H)
	msg2, err := Hash1(suite, []byte(fmt.Sprintf("%d", te)+IDs))
	if err != nil {
		return nil, errors.New("msg2")
	}
	c := suite.G1().Point().Mul(csk3.Mul(csk3, msg2), u1)
	u2 := suite.G1().Point().Add(a.Add(a, b), c)

	u3 := suite.G1().Point().Mul(tsk, u1)

	return &Token{u1: u1, u2: u2, u3: u3}, nil

}

func GenerateBlindToken_User(suite pairing.Suite, pp *PP, tk *Token, y kyber.Scalar, IDs string, te int64) (*BlindToken, kyber.Scalar, error) {
	r := suite.G2().Scalar().Pick(random.New())
	u1, u2, u3 := tk.u1, tk.u2, tk.u3
	os.Stdout.Sync()
	a := suite.G1().Point().Add(u2, u3.Mul(r, u3))
	b1 := suite.G2().Point().Mul(y, pp.cpk2)
	b2 := suite.G2().Point().Mul(r, pp.apk)
	b := suite.G2().Point().Add(b1, b2)
	c := suite.G2().Point().Mul(r, suite.G2().Point().Base())
	d := suite.G1().Point().Mul(r, u1)

	return &BlindToken{
		a: a, b: b, c: c, d: d, IDs: IDs, te: te,
	}, r, nil
}

func GenerateProof_User(suite pairing.Suite, pp *PP, y kyber.Scalar, r kyber.Scalar) (*Proof, error) {
	ra := suite.G2().Scalar().Pick(random.New())
	rb := suite.G2().Scalar().Pick(random.New())
	v1 := suite.G2().Point().Mul(ra, pp.cpk2)
	v2 := suite.G2().Point().Mul(rb, pp.apk)

	msg1, err := v1.MarshalBinary()
	if err != nil {
		return nil, err
	}
	msg2, err := v2.MarshalBinary()
	if err != nil {
		return nil, err
	}
	msg := append(msg1, msg2...)
	tp := time.Now().UnixMicro()
	msg = append(msg, []byte(fmt.Sprintf("%d", tp))...)
	hash := sha256.Sum256(msg)
	clg := suite.G2().Scalar().SetBytes(hash[:])
	u, _ := clg.MarshalBinary()
	print(u)
	v3 := suite.G2().Scalar().Mul(y, clg)
	v3 = suite.G2().Scalar().Add(v3, ra)
	v4 := suite.G2().Scalar().Mul(r, clg)
	v4 = suite.G2().Scalar().Add(v4, rb)
	return &Proof{v1: v1, v2: v2, v3: v3, v4: v4, tp: tp}, nil
}

func Verify(suite pairing.Suite, pp *PP, blindToken *BlindToken, proof *Proof) error {
	left := suite.Pair(blindToken.a, blindToken.c)
	h, _ := Hash1(suite, []byte(fmt.Sprintf("%d", blindToken.te)+blindToken.IDs))
	right_ := pp.cpk3.Mul(h, pp.cpk3)
	right_ = pp.cpk1.Add(pp.cpk1, right_)
	right_ = right_.Add(right_, blindToken.b)
	right := suite.Pair(blindToken.d, right_)
	if !left.Equal(right) {
		fmt.Println("Blind token verification: Failure")
		return errors.New("bls: invalid signature")
	} else {
		fmt.Println("Blind token verification: Success")
	}

	left1 := suite.G2().Point().Mul(proof.v3, pp.cpk2)
	left2 := suite.G2().Point().Mul(proof.v4, pp.apk)
	left = left1.Add(left1, left2)
	msg1, err := proof.v1.MarshalBinary()
	if err != nil {
		return err
	}
	msg2, err := proof.v2.MarshalBinary()
	if err != nil {
		return err
	}
	msg := append(msg1, msg2...)
	msg = append(msg, []byte(fmt.Sprintf("%d", proof.tp))...)
	hash := sha256.Sum256(msg)
	clg := suite.G2().Scalar().SetBytes(hash[:])
	u, _ := clg.MarshalBinary()
	print(u)
	right = suite.G2().Point().Mul(clg, blindToken.b)
	right = suite.G2().Point().Add(right, proof.v1)
	right = suite.G2().Point().Add(right, proof.v2)
	if !left.Equal(right) {
		fmt.Println("Proof verification: Failure")
		return errors.New("Proof verification: Failure")
	} else {
		fmt.Println("Proof verification: Success")

	}

	return nil
}

func Audit(suite pairing.Suite, pp *PP, tk *BlindToken, ask kyber.Scalar, cks2 kyber.Scalar, r kyber.Scalar) kyber.Point {
	Y1 := suite.G2().Point().Mul(suite.G2().Scalar().Neg(ask), tk.c)
	Y2 := suite.G2().Point().Add(tk.b, Y1)
	Y := suite.G2().Point().Mul(suite.G2().Scalar().Inv(cks2), Y2)
	return Y
}
