package tpec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

type PaillierNthRootProof struct {
	PK      *paillier.PublicKey
	U       *big.Int
	A       *big.Int
	Z       *big.Int
	SecBits int
}

func ProvePaillierNthRoot(
	pk *paillier.PublicKey,
	secbits int) (*PaillierNthRootProof, error) {

	proof := &PaillierNthRootProof{
		PK:      pk,
		U:       new(big.Int),
		A:       new(big.Int),
		Z:       new(big.Int),
		SecBits: secbits,
	}

	// Sample random v in N^2.
	v, err := rand.Int(rand.Reader, pk.NSquared)
	if err != nil {
		return nil, err
	}

	// Compute u = v^N mod N^2.
	proof.U.Exp(v, pk.N, pk.NSquared)

	// Could prove multiple instances in parallel, with fewer bits of
	// security per proof. Seems fastest w/ single instance atm, could
	// revisit after optimizing paillier exponentiation.
	err = proof.proveInstance(v)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

func (p *PaillierNthRootProof) Verify() error {
	return p.verifyInstance()
}

func (p *PaillierNthRootProof) proveInstance(v *big.Int) error {
	// Sample a random r in N^2.
	r, err := rand.Int(rand.Reader, p.PK.NSquared)
	if err != nil {
		return err
	}

	// Compute a = r^N mod N^2.
	p.A.Exp(r, p.PK.N, p.PK.NSquared)

	// Construct a k-bit challenge e using the fiat-shamir heuristic.
	e := p.deriveChallenge(p.A.Bytes())

	// Compute z = r * v^e mod N^2
	p.Z.Exp(v, e, p.PK.NSquared)
	p.Z.Mul(p.Z, r)
	p.Z.Mod(p.Z, p.PK.NSquared)

	return nil
}

func (p *PaillierNthRootProof) verifyInstance() error {
	// Compute z^N mod N^2.
	var zn big.Int
	zn.Exp(p.Z, p.PK.N, p.PK.NSquared)

	// Derive k-bit fiat-shamir challenge.
	e := p.deriveChallenge(p.A.Bytes())

	// Compute a * u^e mod N^2
	var aue big.Int
	aue.Exp(p.U, e, p.PK.NSquared)
	aue.Mul(&aue, p.A)
	aue.Mod(&aue, p.PK.NSquared)

	// Fail if z^n != a * u^e mod N^2.
	if zn.Cmp(&aue) != 0 {
		return ErrInvalidPrimalityProof
	}

	return nil
}

func (p *PaillierNthRootProof) deriveChallenge(a []byte) *big.Int {
	var iv [aes.BlockSize]byte

	seed := sha256.Sum256(a)
	block, _ := aes.NewCipher(seed[:])
	stream := cipher.NewCTR(block, iv[:])

	// Use AES-CTR(H(a), 0) to derive random 2^t bit value.
	var eBytes = make([]byte, (p.SecBits+7)/8)
	stream.XORKeyStream(eBytes, eBytes)

	// the bits will be interpreted as big-endian. Trim any excess bits
	// greater than length t from the highest byte.
	mask := uint32(1<<uint(p.SecBits%8)) - 1
	if mask > 0 {
		eBytes[0] &= byte(mask)
	}

	return new(big.Int).SetBytes(eBytes)
}
