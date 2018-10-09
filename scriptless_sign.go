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

type Party1SSSignCtx struct {
	// Input
	msg []byte
	sk  *Party1PrivateKey
	T   *eckey.CompressedPublicKey

	// Sign phase 1
	k1         *eckey.SecretKey
	R1         *eckey.PublicKey
	R1PoK      *DLogPoK
	R1PoKNonce Nonce

	// Sign phase 3
	R2 *eckey.PublicKey
	R3 *eckey.PublicKey

	// Sign phase 5
	SDPrime *big.Int
}

func (sk *Party1PrivateKey) NewSSSignCtx(
	msg []byte,
	T *eckey.CompressedPublicKey) *Party1SSSignCtx {

	return &Party1SSSignCtx{
		msg: msg,
		sk:  sk,
		T:   T,
	}
}

func (c *Party1SSSignCtx) Zero() {
	c.k1.Zero()
}

type Party2SSSignCtx struct {
	// Input
	msg []byte
	sk  *Party2PrivateKey
	t   *eckey.SecretKey
	T   *eckey.CompressedPublicKey

	// Sign phase 2
	R1PoKComm Comm
	k2        *eckey.SecretKey
	R2        *eckey.PublicKey
	R2PoK     *DLogPoK
	r3        *eckey.SecretKey
	R3PoK     *DLogPoK

	// Sign phase 4
	R1 *eckey.PublicKey
}

func (sk *Party2PrivateKey) NewSSSignCtx(
	msg []byte,
	t *eckey.SecretKey,
	T *eckey.CompressedPublicKey) *Party2SSSignCtx {

	return &Party2SSSignCtx{
		msg: msg,
		sk:  sk,
		t:   t,
		T:   T,
	}
}

func (c *Party2SSSignCtx) Zero() {
	c.k2.Zero()
}

func (sk1 *Party1PrivateKey) ScriptlessSign(
	msg []byte,
	t *eckey.SecretKey,
	sk2 *Party2PrivateKey) (*btcec.Signature, *eckey.SecretKey, error) {

	T := t.PublicKey().Compress()

	p1Ctx := sk1.NewSSSignCtx(msg, T)
	defer p1Ctx.Zero()

	sm1, err := p1Ctx.SSSignMsgPhase1(0)
	if err != nil {
		return nil, nil, err
	}

	p2Ctx := sk2.NewSSSignCtx(msg, t, T)
	defer p2Ctx.Zero()

	sm2, err := p2Ctx.SSSignMsgPhase2(0, sm1)
	if err != nil {
		return nil, nil, err
	}

	sm3, err := p1Ctx.SSSignMsgPhase3(0, sm2)
	if err != nil {
		return nil, nil, err
	}

	sm4, err := p2Ctx.SSSignMsgPhase4(0, sm3)
	if err != nil {
		return nil, nil, err
	}

	sm5, err := p1Ctx.SSSignMsgPhase5(0, sm4)
	if err != nil {
		return nil, nil, err
	}

	sig, err := p2Ctx.SSSignMsgPhase6(0, sm5)
	if err != nil {
		return nil, nil, err
	}

	tt, err := p1Ctx.Extract(sig)
	if err != nil {
		return nil, nil, err
	}

	return sig, tt, nil
}

type SSSignMsg1 struct {
	R1PoKComm Comm
}

func (p *Party1SSSignCtx) SSSignMsgPhase1(sid uint64) (*SSSignMsg1, error) {
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

	return &SSSignMsg1{
		R1PoKComm: R1Comm,
	}, nil
}

type SSSignMsg2 struct {
	R2PoK *DLogPoK
	R3PoK *DLogPoK
}

func (p *Party2SSSignCtx) SSSignMsgPhase2(
	sid uint64,
	m1 *SSSignMsg1) (*SSSignMsg2, error) {

	// TODO check sid

	k2, err := NewPrivKey(p.sk.cfg.Q)
	if err != nil {
		return nil, err
	}

	R2PoK, err := NewDLogPK(signPhase2Msg, k2)
	if err != nil {
		return nil, err
	}

	// Compute tr2 = t *r mod q.
	var tr2 = new(big.Int)
	tr2.Mul(
		new(big.Int).SetBytes(k2[:]),
		new(big.Int).SetBytes(p.t[:]),
	)
	tr2.Mod(tr2, p.sk.cfg.Q)

	tr2Bytes := tr2.Bytes()

	r3 := new(eckey.SecretKey)
	copy(r3[eckey.SecretSize-len(tr2Bytes):], tr2Bytes)

	R3PoK, err := NewDLogPK(signPhase2Msg, r3)
	if err != nil {
		return nil, err
	}

	p.R1PoKComm = m1.R1PoKComm
	p.k2 = k2
	p.R2 = k2.PublicKey()
	p.R2PoK = R2PoK
	p.r3 = r3
	p.R3PoK = R3PoK

	return &SSSignMsg2{
		R2PoK: R2PoK,
		R3PoK: R3PoK,
	}, nil
}

type SSSignMsg3 struct {
	R1PoK      *DLogPoK
	R1PoKNonce Nonce
}

func (p *Party1SSSignCtx) SSSignMsgPhase3(
	sid uint64,
	m2 *SSSignMsg2) (*SSSignMsg3, error) {

	err := m2.R2PoK.Verify(signPhase2Msg)
	if err != nil {
		return nil, err
	}

	err = m2.R3PoK.Verify(signPhase2Msg)
	if err != nil {
		return nil, err
	}

	R2, err := m2.R2PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	R3, err := m2.R3PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	p.R2 = R2
	p.R3 = R3

	return &SSSignMsg3{
		R1PoK:      p.R1PoK,
		R1PoKNonce: p.R1PoKNonce,
	}, nil
}

type SSSignMsg4 struct {
	c3 *big.Int
}

func (p *Party2SSSignCtx) SSSignMsgPhase4(
	sid uint64,
	m3 *SSSignMsg3) (*SSSignMsg4, error) {

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
	Rx, _ := btcec.S256().ScalarMult(R1x, R1y, p.r3[:])

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

	return &SSSignMsg4{
		c3: c3,
	}, nil
}

var ErrInvalidPreSignature = errors.New("invalid pre-signature")

type SSSignMsg5 struct {
	SDPrime *big.Int
}

func (p *Party1SSSignCtx) SSSignMsgPhase5(
	sid uint64,
	m4 *SSSignMsg4) (*SSSignMsg5, error) {

	R3x, R3y := p.R3.Coords()
	Rx, _ := btcec.S256().ScalarMult(R3x, R3y, p.k1[:])
	r := new(big.Int).Mod(Rx, p.sk.cfg.Q)

	sPrimeBytes, err := paillier.Decrypt(p.sk.PSK, m4.c3.Bytes())
	if err != nil {
		return nil, err
	}

	// Take s' mod q.
	var sPrime big.Int
	sPrime.SetBytes(sPrimeBytes)
	sPrime.Mod(&sPrime, p.sk.cfg.Q)

	// Compute R2s = s' * R2.
	R2x, R2y := p.R2.Coords()
	R2sx, R2sy := btcec.S256().ScalarMult(R2x, R2y, sPrime.Bytes())
	R2s, err := eckey.NewPublicKeyCoords(R2sx, R2sy)
	if err != nil {
		return nil, err
	}

	// Compute U = r * Q + m * G.
	Qx, Qy := p.sk.PublicKey.X, p.sk.PublicKey.Y
	rQx, rQy := btcec.S256().ScalarMult(Qx, Qy, r.Bytes())
	mGx, mGy := btcec.S256().ScalarBaseMult(p.msg)
	Ux, Uy := btcec.S256().Add(rQx, rQy, mGx, mGy)
	U, err := eckey.NewPublicKeyCoords(Ux, Uy)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(R2s[:], U[:]) {
		return nil, ErrInvalidPreSignature
	}

	var k1Inv big.Int
	k1Inv.SetBytes(p.k1[:])
	k1Inv.ModInverse(&k1Inv, p.sk.cfg.Q)

	sDPrime := new(big.Int)
	sDPrime.Mul(&sPrime, &k1Inv)
	sDPrime.Mod(sDPrime, p.sk.cfg.Q)

	p.SDPrime = sDPrime

	return &SSSignMsg5{
		SDPrime: sDPrime,
	}, nil

	return nil, nil
}

func (p *Party2SSSignCtx) SSSignMsgPhase6(
	sid uint64,
	m5 *SSSignMsg5) (*btcec.Signature, error) {

	// Compute t^(-1) mod q.
	var tInv big.Int
	tInv.SetBytes(p.t[:])
	tInv.ModInverse(&tInv, p.sk.cfg.Q)

	// Compute s'' * t^(-1) mod q.
	s := new(big.Int)
	s.Mul(&tInv, m5.SDPrime)
	s.Mod(s, p.sk.cfg.Q)

	R1x, R1y := p.R1.Coords()
	Rx, _ := btcec.S256().ScalarMult(R1x, R1y, p.r3[:])
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

func (p *Party1SSSignCtx) Extract(
	sig *btcec.Signature) (*eckey.SecretKey, error) {

	// Compute s''^(-1).
	var sDPrimeInv big.Int
	sDPrimeInv.Set(p.SDPrime)
	sDPrimeInv.ModInverse(&sDPrimeInv, p.sk.cfg.Q)

	// Compute t = (s * s''^(-1))^(-1)
	var tInt = new(big.Int)
	tInt.Mul(sig.S, &sDPrimeInv)
	tInt.Mod(tInt, p.sk.cfg.Q)
	tInt.ModInverse(tInt, p.sk.cfg.Q)

	return eckey.NewSecretKeyInt(tInt)
}
