package tpec

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

var ErrInvalidSignature = errors.New("invalid presignature created")

type Party1SignCtx struct {
	// Input
	msg []byte
	sk  *Party1PrivateKey

	// Sign phase 1
	k1         *eckey.SecretKey
	R1         *eckey.PublicKey
	R1PoK      *DLogPoK
	R1PoKNonce Nonce

	// Sign phase 3
	R2 *eckey.PublicKey
}

func (sk *Party1PrivateKey) NewSignCtx(msg []byte) *Party1SignCtx {
	return &Party1SignCtx{
		msg: msg,
		sk:  sk,
	}
}

func (c *Party1SignCtx) Zero() {
	c.k1.Zero()
}

type Party2SignCtx struct {
	// Input
	msg []byte
	sk  *Party2PrivateKey

	// Sign phase 2
	R1PoKComm Comm
	k2        *eckey.SecretKey
	R2        *eckey.PublicKey
	R2PoK     *DLogPoK

	// Sign phase 4
	R1 *eckey.PublicKey
}

func (sk *Party2PrivateKey) NewSignCtx(msg []byte) *Party2SignCtx {
	return &Party2SignCtx{
		msg: msg,
		sk:  sk,
	}
}

func (c *Party2SignCtx) Zero() {
	c.k2.Zero()
}

func (sk1 *Party1PrivateKey) Sign(
	msg []byte,
	sk2 *Party2PrivateKey) (*btcec.Signature, error) {

	p1Ctx := sk1.NewSignCtx(msg)
	defer p1Ctx.Zero()

	sm1, err := p1Ctx.SignMsgPhase1(0)
	if err != nil {
		return nil, err
	}

	p2Ctx := sk2.NewSignCtx(msg)
	defer p2Ctx.Zero()

	sm2, err := p2Ctx.SignMsgPhase2(0, sm1)
	if err != nil {
		return nil, err
	}

	sm3, err := p1Ctx.SignMsgPhase3(0, sm2)
	if err != nil {
		return nil, err
	}

	sm4, err := p2Ctx.SignMsgPhase4(0, sm3)
	if err != nil {
		return nil, err
	}

	sig, err := p1Ctx.SignMsgPhase5(0, sm4)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

type SignMsg1 struct {
	R1PoKComm Comm
}

func (p *Party1SignCtx) SignMsgPhase1(sid uint64) (*SignMsg1, error) {
	// TODO(conner): check sid

	k1, err := NewPrivKey(p.sk.cfg.Q)
	if err != nil {
		return nil, err
	}

	// TODO(conner): include sid?
	R1PoK, err := NewDLogPK(signPhase1Msg, k1)
	if err != nil {
		return nil, err
	}

	R1Comm, R1Nonce, err := Commit(R1PoK.Bytes())
	if err != nil {
		return nil, err
	}

	p.k1 = k1
	p.R1 = k1.PublicKey()
	p.R1PoK = R1PoK
	p.R1PoKNonce = R1Nonce

	return &SignMsg1{
		R1PoKComm: R1Comm,
	}, nil
}

type SignMsg2 struct {
	R2PoK *DLogPoK
}

func (p *Party2SignCtx) SignMsgPhase2(
	sid uint64,
	m1 *SignMsg1) (*SignMsg2, error) {

	// TODO check sid

	k2, err := NewPrivKey(p.sk.cfg.Q)
	if err != nil {
		return nil, err
	}

	R2PoK, err := NewDLogPK(signPhase2Msg, k2)
	if err != nil {
		return nil, err
	}

	p.R1PoKComm = m1.R1PoKComm
	p.k2 = k2
	p.R2 = k2.PublicKey()
	p.R2PoK = R2PoK

	return &SignMsg2{
		R2PoK: R2PoK,
	}, nil
}

type SignMsg3 struct {
	R1PoK      *DLogPoK
	R1PoKNonce Nonce
}

func (p *Party1SignCtx) SignMsgPhase3(
	sid uint64,
	m2 *SignMsg2) (*SignMsg3, error) {

	err := m2.R2PoK.Verify(signPhase2Msg)
	if err != nil {
		return nil, err
	}

	R2, err := m2.R2PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	p.R2 = R2

	return &SignMsg3{
		R1PoK:      p.R1PoK,
		R1PoKNonce: p.R1PoKNonce,
	}, nil
}

type SignMsg4 struct {
	c3 *big.Int
}

func (p *Party2SignCtx) SignMsgPhase4(
	sid uint64,
	m3 *SignMsg3) (*SignMsg4, error) {

	m := new(big.Int).SetBytes(p.msg)

	// Sample rho in q^2.
	rho, err := rand.Int(rand.Reader, p.sk.cfg.QSquared)
	if err != nil {
		return nil, err
	}

	// Compute rho * q.
	var rhoq big.Int
	rhoq.Mul(rho, p.sk.cfg.Q)
	rhoq.Mod(&rhoq, p.sk.cfg.QSquared)

	// Compute k2^(-1).
	var k2Inv big.Int
	k2Inv.SetBytes(p.k2[:])
	k2Inv.ModInverse(&k2Inv, p.sk.cfg.Q)

	// Compute pt = rho * q + [k2^(-1) * m mod q].
	var pt big.Int
	pt.Mul(&k2Inv, m)
	pt.Mod(&pt, p.sk.cfg.Q)
	pt.Add(&pt, &rhoq)

	// Encrypt the plaintext to get c1 in parallel.
	c1Chan := make(chan *big.Int)
	go func() {
		c1Bytes, err := paillier.Encrypt(p.sk.PPK, pt.Bytes())
		if err != nil {
			panic(err)
		}

		c1 := new(big.Int).SetBytes(c1Bytes)
		c1Chan <- c1
	}()

	err = p.R1PoKComm.Verify(m3.R1PoK.Bytes(), &m3.R1PoKNonce)
	if err != nil {
		return nil, err
	}

	err = m3.R1PoK.Verify(signPhase1Msg)
	if err != nil {
		return nil, err
	}

	R1, err := m3.R1PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	R1x, R1y := R1.Coords()
	Rx, _ := btcec.S256().ScalarMult(R1x, R1y, p.k2[:])

	r := new(big.Int).Mod(Rx, p.sk.cfg.Q)

	var x2Int big.Int
	x2Int.SetBytes(p.sk.X2SK[:])

	// Compute v = k2^(-1) * r * x2 mod q.
	var v big.Int
	v.Mul(&k2Inv, r)
	v.Mul(&v, &x2Int)
	v.Mod(&v, p.sk.cfg.Q)

	// Compute c2 = ckey ^ v mod N^2, multiplying the decrypted value by v.
	var c2 big.Int
	c2.Exp(p.sk.CKey, &v, p.sk.PPK.NSquared)

	// Receive ciphertext c1 from background.
	c1 := <-c1Chan

	// Finally, compute c3 = c1 * c2 mod N^2, summing the decrypted
	// plaintexts.
	c3 := new(big.Int).Mul(c1, &c2)
	c3.Mod(c3, p.sk.PPK.NSquared)

	p.R1 = R1

	return &SignMsg4{
		c3: c3,
	}, nil
}

func (p *Party1SignCtx) SignMsgPhase5(
	sid uint64,
	m4 *SignMsg4) (*btcec.Signature, error) {

	s1Bytes, err := paillier.Decrypt(p.sk.PSK, m4.c3.Bytes())
	if err != nil {
		return nil, err
	}

	var s1 big.Int
	s1.SetBytes(s1Bytes)

	var k1Inv big.Int
	k1Inv.SetBytes(p.k1[:])
	k1Inv.ModInverse(&k1Inv, p.sk.cfg.Q)

	var s2 big.Int
	s2.Mul(&k1Inv, &s1)
	s2.Mod(&s2, p.sk.cfg.Q)

	var qMinusS big.Int
	qMinusS.Sub(p.sk.cfg.Q, &s2)

	var s = new(big.Int)
	if s2.Cmp(&qMinusS) <= 0 {
		s.Set(&s2)
	} else {
		s.Set(&qMinusS)
	}

	R2x, R2y := p.R2.Coords()
	Rx, _ := btcec.S256().ScalarMult(R2x, R2y, p.k1[:])
	r := new(big.Int).Mod(Rx, p.sk.cfg.Q)

	sig := &btcec.Signature{
		R: r,
		S: s,
	}

	validEcdsaSig := sig.Verify(p.msg, p.sk.PublicKey)
	if !validEcdsaSig {
		return nil, ErrInvalidSignature
	}

	return sig, nil
}
