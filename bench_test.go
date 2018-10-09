package tpec_test

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/cfromknecht/tpec"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

var (
	sk1 *tpec.Party1PrivateKey
	sk2 *tpec.Party2PrivateKey
	sig *btcec.Signature
	tt  *eckey.SecretKey
	err error
)

func newConfig() *tpec.Config {
	params := btcec.S256().CurveParams
	q := new(big.Int).Set(params.N)
	q3 := new(big.Int).Div(q, big.NewInt(3))
	qSquared := new(big.Int).Mul(q, q)

	return &tpec.Config{
		Q:              q,
		Q3:             q3,
		QSquared:       qSquared,
		NPaillierBits:  2048,
		NthRootSecBits: 128,
		RangeSecBits:   40,
	}
}

func TestKeyGen(t *testing.T) {
	cfg := newConfig()

	var p1 = tpec.NewParty1(cfg)
	var p2 = tpec.NewParty2(cfg)

	sk1, err = p1.GenKey(p2, nil, nil)
	if err != nil {
		t.Fatalf("unable to generate keys: %v", err)
	}

	sk2, err = p2.PrivateKey()
	if err != nil {
		t.Fatalf("unable to get p2 privkey: %v", err)
	}

	q1Bytes := sk1.PublicKey.SerializeCompressed()
	q2Bytes := sk2.PublicKey.SerializeCompressed()

	if !bytes.Equal(q1Bytes, q2Bytes) {
		t.Fatalf("parties have different pubkeys, p1=%x p2=%x",
			q1Bytes, q2Bytes)
	}

	x1Ptxt, err := paillier.Decrypt(sk1.PSK, sk2.CKey.Bytes())
	if err != nil {
		t.Fatalf("unable to decrypt p2's ciphertext: %v", err)
	}

	if !bytes.Equal(sk1.X1SK[:], x1Ptxt) {
		t.Fatalf("ctxt does not contain p1's private key, "+
			"x1=%x ptxt=%x", sk1.X1SK[:], x1Ptxt)
	}
}

func TestSign(t *testing.T) {
	cfg := newConfig()

	var p1 = tpec.NewParty1(cfg)
	var p2 = tpec.NewParty2(cfg)

	sk1, err = p1.GenKey(p2, nil, nil)
	if err != nil {
		t.Fatalf("unable to generate keys: %v", err)
	}

	sk2, err = p2.PrivateKey()
	if err != nil {
		t.Fatalf("unable to get p2 privkey: %v", err)
	}

	msg := []byte("hello 2pecdsa")
	digest := sha256.Sum256(msg)

	sig, err = sk1.Sign(digest[:], sk2)
	if err != nil {
		t.Fatalf("unable to sign msg: %v", err)
	}

	if !sig.Verify(digest[:], sk1.PublicKey) {
		t.Fatalf("invalid 2P-ECDSA signature")
	}
}

func TestScriptlessSign(t *testing.T) {
	cfg := newConfig()

	r, err := tpec.NewPrivKey(cfg.Q)
	if err != nil {
		t.Fatalf("unable to generate secret: %v", err)
	}

	var p1 = tpec.NewParty1(cfg)
	var p2 = tpec.NewParty2(cfg)

	sk1, err = p1.GenKey(p2, nil, nil)
	if err != nil {
		t.Fatalf("unable to generate keys: %v", err)
	}

	sk2, err = p2.PrivateKey()
	if err != nil {
		t.Fatalf("unable to get p2 privkey: %v", err)
	}

	msg := []byte("hello 2pecdsa")
	digest := sha256.Sum256(msg)

	sig, rr, err := sk1.ScriptlessSign(digest[:], r, sk2)
	if err != nil {
		t.Fatalf("unable to sign msg: %v", err)
	}

	if !sig.Verify(digest[:], sk1.PublicKey) {
		t.Fatalf("invalid 2P-ECDSA signature")
	}

	if !bytes.Equal(r[:], rr[:]) {
		t.Fatalf("extracted secret does not match original, "+
			"original=%x extracted=%x", r, rr)
	}
}

func BenchmarkKeyGen(b *testing.B) {
	cfg := newConfig()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var p1 = tpec.NewParty1(cfg)
		var p2 = tpec.NewParty2(cfg)

		sk1, err = p1.GenKey(p2, nil, nil)
		if err != nil {
			b.Fatalf("unable to generate keys: %v", err)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	cfg := newConfig()

	var p1 = tpec.NewParty1(cfg)
	var p2 = tpec.NewParty2(cfg)

	sk1, err = p1.GenKey(p2, nil, nil)
	if err != nil {
		b.Fatalf("unable to generate keys: %v", err)
	}

	sk2, err = p2.PrivateKey()
	if err != nil {
		b.Fatalf("unable to get p2 privkey: %v", err)
	}

	msg := []byte("hello 2pecdsa")
	digest := sha256.Sum256(msg)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig, err = sk1.Sign(digest[:], sk2)
		if err != nil {
			b.Fatalf("unable to sign msg: %v", err)
		}
	}
}

func BenchmarkScriptlessSign(b *testing.B) {
	cfg := newConfig()

	t, err := tpec.NewPrivKey(cfg.Q)
	if err != nil {
		b.Fatalf("unable to generate secret: %v", err)
	}

	var p1 = tpec.NewParty1(cfg)
	var p2 = tpec.NewParty2(cfg)

	sk1, err = p1.GenKey(p2, nil, nil)
	if err != nil {
		b.Fatalf("unable to generate keys: %v", err)
	}

	sk2, err = p2.PrivateKey()
	if err != nil {
		b.Fatalf("unable to get p2 privkey: %v", err)
	}

	msg := []byte("hello 2pecdsa")
	digest := sha256.Sum256(msg)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig, tt, err = sk1.ScriptlessSign(digest[:], t, sk2)
		if err != nil {
			b.Fatalf("unable to sign msg: %v", err)
		}
	}
}
