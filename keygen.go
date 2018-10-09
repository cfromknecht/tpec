package tpec

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

var (
	ErrInvalidOTMac = errors.New("invalid one-time MAC")

	ErrFinalKeyMismatch = errors.New("final OT key doesn't match")

	ErrKeyNotGenerated = errors.New("private key has not been generated")
)

func (p *Party1) GenKey(
	p2 *Party2,
	x1, x2 *eckey.SecretKey) (*Party1PrivateKey, error) {

	p.x1 = x1
	p2.x2 = x2

	m1, err := p.KeyGenPhase1(0)
	if err != nil {
		return nil, err
	}

	m2, err := p2.KeyGenPhase2(0, m1)
	if err != nil {
		return nil, err
	}

	m3, err := p.KeyGenPhase3(0, m2)
	if err != nil {
		return nil, err
	}

	m4, err := p2.KeyGenPhase4(0, m3)
	if err != nil {
		return nil, err
	}

	m5, err := p.KeyGenPhase5(0, m4)
	if err != nil {
		return nil, err
	}

	m6, err := p2.KeyGenPhase6(0, m5)
	if err != nil {
		return nil, err
	}

	m7, err := p.KeyGenPhase7(0, m6)
	if err != nil {
		return nil, err
	}

	err = p2.KeyGenPhase8(0, m7)
	if err != nil {
		return nil, err
	}

	Qcpk := p.Q.Compress()

	Q, err := btcec.ParsePubKey(Qcpk[:], btcec.S256())
	if err != nil {
		return nil, err
	}

	return &Party1PrivateKey{
		cfg:       p.cfg,
		PSK:       p.PSK,
		X1SK:      p.x1,
		PublicKey: Q,
	}, nil
}

type KeyGenMsg1 struct {
	X1PoKComm Comm
}

func (p *Party1) KeyGenPhase1(
	sid uint64) (*KeyGenMsg1, error) {

	// TODO(conner): check sid

	var x1 *eckey.SecretKey
	var err error
	if p.x1 != nil {
		x1 = p.x1
	} else {
		x1, err = NewPrivKey(p.cfg.Q3)
		if err != nil {
			return nil, err
		}
	}

	// TODO(conner): append sid?
	X1PoK, err := NewDLogPK(keyGenPhase1Msg, x1)
	if err != nil {
		return nil, err
	}

	X1Comm, X1Nonce, err := Commit(X1PoK.Bytes())
	if err != nil {
		return nil, err
	}

	p.x1 = x1
	p.X1 = x1.PublicKey()
	p.X1PoK = X1PoK
	p.X1Nonce = X1Nonce

	return &KeyGenMsg1{
		X1PoKComm: X1Comm,
	}, nil
}

type KeyGenMsg2 struct {
	X2PoK      *DLogPoK
	RPChalComm Comm
}

func (p *Party2) KeyGenPhase2(
	sid uint64,
	m1 *KeyGenMsg1) (*KeyGenMsg2, error) {

	// TODO(conner): check sid

	var x2 *eckey.SecretKey
	var err error
	if p.x2 != nil {
		x2 = p.x2
	} else {
		x2, err = NewPrivKey(p.cfg.Q)
		if err != nil {
			return nil, err
		}
	}

	// TODO(conner): append sid?
	X2PoK, err := NewDLogPK(keyGenPhase2Msg, x2)
	if err != nil {
		return nil, err
	}

	rpVerifier, err := NewRangeProofVerifier(
		p.cfg.Q3, p.cfg.RangeSecBits,
	)
	if err != nil {
		return nil, err
	}

	p.X1PoKComm = m1.X1PoKComm
	p.x2 = x2
	p.X2 = x2.PublicKey()
	p.X2PoK = X2PoK
	p.RPVerifier = rpVerifier

	return &KeyGenMsg2{
		X2PoK:      X2PoK,
		RPChalComm: p.RPVerifier.Comm,
	}, nil
}

type KeyGenMsg3 struct {
	X1PoK       *DLogPoK
	X1PoKNonce  Nonce
	PProof      *PaillierNthRootProof
	ckey        []byte
	RPCtxtPairs []CiphertextPair
}

func (p *Party1) KeyGenPhase3(
	sid uint64,
	m2 *KeyGenMsg2) (*KeyGenMsg3, error) {

	err := m2.X2PoK.Verify(keyGenPhase2Msg)
	if err != nil {
		return nil, err
	}

	psk, err := paillier.GenerateKey(rand.Reader, p.cfg.NPaillierBits)
	if err != nil {
		return nil, err
	}

	ckey, ckeyNonce, err := paillier.EncryptAndNonce(&psk.PublicKey, p.x1[:])
	if err != nil {
		return nil, err
	}

	proof, err := ProvePaillierNthRoot(&psk.PublicKey, p.cfg.NthRootSecBits)
	if err != nil {
		return nil, err
	}

	X2, err := m2.X2PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	x1 := new(big.Int).SetBytes(p.x1[:])
	rpProver, err := NewRangeProofProver(
		x1, ckeyNonce, p.cfg.Q, p.cfg.Q3, psk, m2.RPChalComm,
		p.cfg.RangeSecBits,
	)
	if err != nil {
		return nil, err
	}

	p.X2 = X2
	p.PSK = psk
	p.CKey = new(big.Int).SetBytes(ckey)
	p.CKeyNonce = ckeyNonce
	p.RPProver = rpProver

	return &KeyGenMsg3{
		X1PoK:       p.X1PoK,
		X1PoKNonce:  p.X1Nonce,
		PProof:      proof,
		ckey:        ckey,
		RPCtxtPairs: p.RPProver.CtxtPairs,
	}, nil
}

type KeyGenMsg4 struct {
	RPChallenge BitSlice
	RPChalNonce Nonce
	CPrime      *big.Int
	ABComm      Comm
}

func (p *Party2) KeyGenPhase4(
	sid uint64,
	m3 *KeyGenMsg3) (*KeyGenMsg4, error) {

	err := p.X1PoKComm.Verify(m3.X1PoK.Bytes(), &m3.X1PoKNonce)
	if err != nil {
		return nil, err
	}

	err = m3.X1PoK.Verify(keyGenPhase1Msg)
	if err != nil {
		return nil, err
	}

	err = m3.PProof.Verify()
	if err != nil {
		return nil, err
	}

	X1, err := m3.X1PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	ckey := new(big.Int).SetBytes(m3.ckey)
	c := new(big.Int).Set(ckey)

	p.RPVerifier.ReceiveCtxt(
		c, m3.PProof.PK, m3.RPCtxtPairs,
	)

	a, err := rand.Int(rand.Reader, p.cfg.Q)
	if err != nil {
		return nil, err
	}
	b, err := rand.Int(rand.Reader, p.cfg.QSquared)
	if err != nil {
		return nil, err
	}

	// Compute c' = b * (c^a) mod N^2.
	cPrime := new(big.Int).Set(c)
	cPrime.Exp(cPrime, a, m3.PProof.PK.NSquared)

	tmp := new(big.Int)
	tmp.Exp(m3.PProof.PK.G, b, m3.PProof.PK.NSquared)

	cPrime.Mul(cPrime, tmp)
	cPrime.Mod(cPrime, m3.PProof.PK.NSquared)

	// Commit to a and b.
	var data []byte
	data = append(data, a.Bytes()...)
	data = append(data, b.Bytes()...)
	abComm, abNonce, err := Commit(data)
	if err != nil {
		return nil, err
	}

	p.X1 = X1
	p.PPK = m3.PProof.PK
	p.CKey = ckey

	p.CPrime = cPrime
	p.A = a
	p.B = b
	p.ABNonce = abNonce

	return &KeyGenMsg4{
		RPChallenge: p.RPVerifier.Challenge,
		RPChalNonce: p.RPVerifier.Nonce,
		CPrime:      cPrime,
		ABComm:      abComm,
	}, nil
}

type KeyGenMsg5 struct {
	RPProofPairs []ProofPair
	AlphaComm    Comm
}

func (p *Party1) KeyGenPhase5(
	sid uint64,
	m4 *KeyGenMsg4) (*KeyGenMsg5, error) {

	proofPairs, err := p.RPProver.Prove(m4.RPChallenge, &m4.RPChalNonce)
	if err != nil {
		return nil, err
	}

	alphaBytes, err := paillier.Decrypt(p.PSK, m4.CPrime.Bytes())
	if err != nil {
		return nil, err
	}

	// add comment later
	alphaSk := new(big.Int).SetBytes(alphaBytes)
	alphaSk.Mod(alphaSk, p.cfg.Q)

	alpha, err := eckey.NewSecretKeyInt(alphaSk)
	if err != nil {
		return nil, err
	}

	alphaPK := alpha.PublicKey().Compress()

	alphaComm, alphaNonce, err := Commit(alphaPK[:])
	if err != nil {
		return nil, err
	}

	p.Alpha = new(big.Int).SetBytes(alphaBytes)
	p.AlphaPK = alphaPK
	p.AlphaNonce = alphaNonce
	p.ABComm = m4.ABComm

	return &KeyGenMsg5{
		RPProofPairs: proofPairs,
		AlphaComm:    alphaComm,
	}, nil
}

type KeyGenMsg6 struct {
	A       *big.Int
	B       *big.Int
	ABNonce Nonce
}

func (p *Party2) KeyGenPhase6(
	sid uint64,
	m5 *KeyGenMsg5) (*KeyGenMsg6, error) {

	err := p.RPVerifier.Verify(m5.RPProofPairs)
	if err != nil {
		return nil, err
	}

	p.AlphaComm = m5.AlphaComm

	return &KeyGenMsg6{
		A:       p.A,
		B:       p.B,
		ABNonce: p.ABNonce,
	}, nil
}

type KeyGenMsg7 struct {
	AlphaPK    *eckey.CompressedPublicKey
	AlphaNonce Nonce
}

func (p *Party1) KeyGenPhase7(
	sid uint64,
	m6 *KeyGenMsg6) (*KeyGenMsg7, error) {

	var data []byte
	data = append(data, m6.A.Bytes()...)
	data = append(data, m6.B.Bytes()...)
	err := p.ABComm.Verify(data, &m6.ABNonce)
	if err != nil {
		return nil, err
	}

	var x1Int big.Int
	x1Int.SetBytes(p.x1[:])

	// Compute a' = a * x1 + b.
	var alphaPrime big.Int
	alphaPrime.Mul(m6.A, &x1Int)
	alphaPrime.Add(&alphaPrime, m6.B)

	if alphaPrime.Cmp(p.Alpha) != 0 {
		return nil, ErrInvalidOTMac
	}

	X2x, X2y := p.X2.Coords()
	Qx, Qy := btcec.S256().ScalarMult(X2x, X2y, p.x1[:])

	p.Q, err = eckey.NewPublicKeyCoords(Qx, Qy)
	if err != nil {
		return nil, err
	}

	return &KeyGenMsg7{
		AlphaPK:    p.AlphaPK,
		AlphaNonce: p.AlphaNonce,
	}, nil
}

func (p *Party2) KeyGenPhase8(
	sid uint64,
	m7 *KeyGenMsg7) error {

	err := p.AlphaComm.Verify(m7.AlphaPK[:], &m7.AlphaNonce)
	if err != nil {
		return err
	}

	X1x, X1y := p.X1.Coords()

	// Compute QQ = a*X1 + b*G.
	aQx, aQy := btcec.S256().ScalarMult(X1x, X1y, p.A.Bytes())
	Bx, By := btcec.S256().ScalarBaseMult(p.B.Bytes())
	QQx, QQy := btcec.S256().Add(aQx, aQy, Bx, By)

	QQ, err := eckey.NewPublicKeyCoords(QQx, QQy)
	if err != nil {
		return err
	}
	QQC := QQ.Compress()

	if !bytes.Equal(m7.AlphaPK[:], QQC[:]) {
		return ErrFinalKeyMismatch
	}

	Qx, Qy := btcec.S256().ScalarMult(X1x, X1y, p.x2[:])
	Q, err := eckey.NewPublicKeyCoords(Qx, Qy)
	if err != nil {
		return err
	}

	p.Q = Q

	return nil
}

func (p *Party2) PrivateKey() (*Party2PrivateKey, error) {
	switch {
	case p.PPK == nil:
		return nil, ErrKeyNotGenerated
	case p.CKey == nil:
		return nil, ErrKeyNotGenerated
	case p.x2 == nil:
		return nil, ErrKeyNotGenerated
	case p.Q == nil:
		return nil, ErrKeyNotGenerated
	}

	Qcpk := p.Q.Compress()
	Q, err := btcec.ParsePubKey(Qcpk[:], btcec.S256())
	if err != nil {
		return nil, err
	}

	return &Party2PrivateKey{
		cfg:       p.cfg,
		PPK:       p.PPK,
		CKey:      p.CKey,
		X2SK:      p.x2,
		PublicKey: Q,
	}, nil
}
