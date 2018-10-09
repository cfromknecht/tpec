package tpec

import (
	"crypto/sha256"
	"errors"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/NebulousLabs/hdkey/schnorr"
)

var ErrInvalidPoK = errors.New("invalid proof of knowledge")

type DLogPoK struct {
	PK  eckey.CompressedPublicKey
	Sig schnorr.Signature
}

func NewDLogPK(plaintext []byte, sk *eckey.SecretKey) (*DLogPoK, error) {
	pk := sk.PublicKey().Compress()

	msg := dlogPokMsg(plaintext, pk)
	sig, err := schnorr.Sign(sk, msg)
	if err != nil {
		return nil, err
	}

	return &DLogPoK{
		PK:  *pk,
		Sig: *sig,
	}, nil
}

func (p *DLogPoK) Verify(plaintext []byte) error {
	pk, err := p.PK.Uncompress()
	if err != nil {
		return err
	}

	msg := dlogPokMsg(plaintext, &p.PK)
	return schnorr.Verify(&p.Sig, pk, msg)
}

func (p *DLogPoK) Bytes() []byte {
	var b = make([]byte, len(p.PK)+len(p.Sig))
	offset := copy(b, p.PK[:])
	copy(b[offset:], p.Sig[:])
	return b
}

func dlogPokMsg(plaintext []byte, pk *eckey.CompressedPublicKey) []byte {
	h := sha256.New()
	h.Write(pk[:])
	h.Write(plaintext)
	return h.Sum(nil)
}
