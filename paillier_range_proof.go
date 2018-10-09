package tpec

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"sync"

	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

var (
	ErrInvalidRangeProof = errors.New("invalid range proof")

	ErrInvalidProofPair = errors.New("cannot prove for invalid proof pair")
)

func NewRangeProofVerifier(
	q3 *big.Int,
	accuracy int) (*RangeProofVerifier, error) {

	challenge, err := randBitSlice(accuracy)
	if err != nil {
		return nil, err
	}

	comm, nonce, err := Commit(challenge)
	if err != nil {
		return nil, err
	}

	return &RangeProofVerifier{
		Q3:        q3,
		Challenge: challenge,
		Comm:      comm,
		Nonce:     nonce,
		Accuracy:  accuracy,
	}, nil
}

func (p *RangeProofVerifier) ReceiveCtxt(
	c *big.Int,
	ppk *paillier.PublicKey,
	ctxtPairs []CiphertextPair) {

	p.C = c
	p.PPK = ppk
	// TODO(conner): verify nil-ness of ctxts
	p.CtxtPairs = ctxtPairs
}

type RangeProofVerifier struct {
	C         *big.Int
	PPK       *paillier.PublicKey
	Q3        *big.Int
	Challenge BitSlice
	Comm      Comm
	Nonce     Nonce
	Accuracy  int

	CtxtPairs []CiphertextPair
}

type RangeProofProver struct {
	X   *big.Int
	R   *big.Int
	PSK *paillier.PrivateKey
	Q   *big.Int
	Q3  *big.Int

	ChallengeComm Comm
	Accuracy      int

	SecPairs  []SecretPair
	CtxtPairs []CiphertextPair
}

type SecretPair struct {
	W1 *big.Int
	R1 *big.Int
	W2 *big.Int
	R2 *big.Int
}

func NewSecretPairs(size int) []SecretPair {
	return make([]SecretPair, size)
}

type CiphertextPair struct {
	C1 *big.Int
	C2 *big.Int
}

func NewCiphertextPairs(size int) []CiphertextPair {
	return make([]CiphertextPair, size)
}

type BitSlice []byte

func (b BitSlice) Bit(i int) byte {
	byt := i / 8
	bit := i % 8
	return (b[byt] >> uint(8-bit)) & 0x01
}

func NewRangeProofProver(
	x *big.Int,
	r *big.Int,
	q *big.Int,
	q3 *big.Int,
	psk *paillier.PrivateKey,
	comm Comm,
	accuracy int) (*RangeProofProver, error) {

	secPairs := NewSecretPairs(accuracy)
	ctxtPairs := NewCiphertextPairs(accuracy)

	flipBits, err := randBitSlice(accuracy)
	if err != nil {
		return nil, err
	}

	prover := &RangeProofProver{
		X:             x,
		R:             r,
		Q:             q,
		Q3:            q3,
		PSK:           psk,
		ChallengeComm: comm,
		Accuracy:      accuracy,
		SecPairs:      secPairs,
		CtxtPairs:     ctxtPairs,
	}

	var wg sync.WaitGroup
	var errChan = make(chan error, prover.Accuracy)
	for i := 0; i < prover.Accuracy; i++ {
		wg.Add(1)
		go func(ii int) {
			defer wg.Done()
			flipi := flipBits.Bit(ii)
			err := prover.initInstance(ii, flipi)
			if err != nil {
				errChan <- err
			}
		}(i)
	}
	go func() {
		wg.Wait()
		close(errChan)
	}()
	for err := range errChan {
		return nil, err
	}

	return prover, nil
}

func (p *RangeProofProver) initInstance(i int, flipi byte) error {
	// Sample w1 in {q3, ... , 2*q3}.
	w1, err := rand.Int(rand.Reader, p.Q3)
	if err != nil {
		return err
	}
	w1.Add(w1, p.Q3)

	// Compute w2 = w1 - q3.
	w2 := new(big.Int)
	w2.Sub(w1, p.Q3)

	// Sample r1 and r2 in N.
	r1, err := rand.Int(rand.Reader, p.PSK.PublicKey.N)
	if err != nil {
		return err
	}

	r2, err := rand.Int(rand.Reader, p.PSK.PublicKey.N)
	if err != nil {
		return err
	}

	// Swap the position of 1 and 2 with probability 1/2.
	switch flipi {
	case 0:
		p.SecPairs[i] = SecretPair{
			W1: w1,
			R1: r1,
			W2: w2,
			R2: r2,
		}
	case 1:
		p.SecPairs[i] = SecretPair{
			W1: w2,
			R1: r2,
			W2: w1,
			R2: r1,
		}
	}

	// Compute c1 = Enc(w1, r1) and c2 = Enc(w2, r2).
	c1, err := paillier.EncryptWithNonce(
		&p.PSK.PublicKey, p.SecPairs[i].R1, p.SecPairs[i].W1.Bytes(),
	)
	if err != nil {
		return err
	}
	c2, err := paillier.EncryptWithNonce(
		&p.PSK.PublicKey, p.SecPairs[i].R2, p.SecPairs[i].W2.Bytes(),
	)
	if err != nil {
		return err
	}

	p.CtxtPairs[i] = CiphertextPair{
		C1: c1,
		C2: c2,
	}

	return nil
}

type ProofPair struct {
	J  byte
	W1 *big.Int
	R1 *big.Int
	W2 *big.Int
	R2 *big.Int
}

func NewProofPairs(size int) []ProofPair {
	return make([]ProofPair, size)
}

type RangeProof struct {
	CtxtPairs  []CiphertextPair
	ProofPairs []ProofPair
}

func (p *RangeProofProver) Prove(challenge BitSlice, nonce *Nonce) ([]ProofPair, error) {
	err := p.ChallengeComm.Verify(challenge, nonce)
	if err != nil {
		return nil, err
	}

	proofPairs := NewProofPairs(p.Accuracy)

	var wg sync.WaitGroup
	var errChan = make(chan error, p.Accuracy)
	for i := 0; i < p.Accuracy; i++ {
		wg.Add(1)
		go func(ii int) {
			defer wg.Done()
			ei := challenge.Bit(ii)
			err := p.proveInstance(ii, ei, proofPairs)
			if err != nil {
				errChan <- err
			}
		}(i)
	}
	go func() {
		wg.Wait()
		close(errChan)
	}()
	for err := range errChan {
		return nil, err
	}

	return proofPairs, nil
}

func (p *RangeProofProver) proveInstance(
	i int, ei byte, proofPairs []ProofPair) error {

	lower := p.Q3
	upper := new(big.Int).Add(p.Q3, p.Q3)

	switch ei {
	case 0:
		proofPairs[i] = ProofPair{
			J:  0,
			W1: p.SecPairs[i].W1,
			R1: p.SecPairs[i].R1,
			W2: p.SecPairs[i].W2,
			R2: p.SecPairs[i].R2,
		}
	case 1:
		// Compute w1 + x.
		w1x := new(big.Int)
		w1x.Add(p.SecPairs[i].W1, p.X)

		// Compute w2 + x.
		w2x := new(big.Int)
		w2x.Add(p.SecPairs[i].W2, p.X)

		// Check if l <= w1 + x <= 2*l.
		use1 := lower.Cmp(w1x) <= 0 && w1x.Cmp(upper) < 0

		// Check if l <= w2 + x <= 2*l.
		use2 := lower.Cmp(w2x) <= 0 && w2x.Cmp(upper) < 0

		switch {
		case use1 && use2:
			return ErrInvalidProofPair
		case use1:
			r := new(big.Int).Mul(p.R, p.SecPairs[i].R1)
			r.Mod(r, p.PSK.PublicKey.N)

			proofPairs[i] = ProofPair{
				J:  1,
				W1: w1x,
				R1: r,
			}
		case use2:
			r := new(big.Int).Mul(p.R, p.SecPairs[i].R2)
			r.Mod(r, p.PSK.PublicKey.N)

			proofPairs[i] = ProofPair{
				J:  2,
				W2: w2x,
				R2: r,
			}
		default:
			return ErrInvalidProofPair
		}
	}

	return nil
}

func (p *RangeProofVerifier) Verify(proofPairs []ProofPair) error {
	var wg sync.WaitGroup
	var errChan = make(chan error, p.Accuracy)
	for i := 0; i < p.Accuracy; i++ {
		wg.Add(1)
		go func(ii int) {
			defer wg.Done()
			proofPair := &proofPairs[ii]
			err := p.verifyInstance(ii, proofPair)
			if err != nil {
				errChan <- err
			}
		}(i)
	}
	go func() {
		wg.Wait()
		close(errChan)
	}()
	for err := range errChan {
		return err
	}

	return nil
}

func (p *RangeProofVerifier) verifyInstance(
	i int, proofPair *ProofPair) error {

	lower := p.Q3
	upper := new(big.Int).Add(p.Q3, p.Q3)

	ctxtPair := p.CtxtPairs[i]

	ei := p.Challenge.Bit(i)
	switch {
	case ei == 0 && proofPair.J == 0:
		if proofPair.W1 == nil || proofPair.R1 == nil ||
			proofPair.W2 == nil || proofPair.R2 == nil {
			return ErrInvalidRangeProof
		}

		// Check if l <= w1 <= 2*l.
		validW1Low := zero.Cmp(proofPair.W1) <= 0 &&
			proofPair.W1.Cmp(lower) < 0
		validW1High := lower.Cmp(proofPair.W1) <= 0 &&
			proofPair.W1.Cmp(upper) < 0

		// Check if l <= w2 <= 2*l.
		validW2Low := zero.Cmp(proofPair.W2) <= 0 &&
			proofPair.W2.Cmp(lower) < 0
		validW2High := lower.Cmp(proofPair.W2) <= 0 &&
			proofPair.W2.Cmp(upper) < 0

		validW1 := validW1Low == !validW1High
		validW2 := validW2Low == !validW2High

		c1, err := paillier.EncryptWithNonce(
			p.PPK, proofPair.R1, proofPair.W1.Bytes(),
		)
		if err != nil {
			return err
		}
		c2, err := paillier.EncryptWithNonce(
			p.PPK, proofPair.R2, proofPair.W2.Bytes(),
		)
		if err != nil {
			return err
		}

		validC1 := c1.Cmp(ctxtPair.C1) == 0
		validC2 := c2.Cmp(ctxtPair.C2) == 0

		if !validW1 || !validW2 || !validC1 || !validC2 {
			return ErrInvalidRangeProof
		}

	case ei == 1 && proofPair.J == 1:
		if proofPair.W1 == nil || proofPair.R1 == nil ||
			proofPair.W2 != nil || proofPair.R2 != nil {
			return ErrInvalidRangeProof
		}

		// Check if l <= w1 <= 2*l.
		validW1 := lower.Cmp(proofPair.W1) <= 0 &&
			proofPair.W1.Cmp(upper) < 0

		cc1 := new(big.Int).Mul(p.C, ctxtPair.C1)
		cc1.Mod(cc1, p.PPK.NSquared)

		cj, err := paillier.EncryptWithNonce(
			p.PPK, proofPair.R1, proofPair.W1.Bytes(),
		)
		if err != nil {
			return err
		}

		validCj := cc1.Cmp(cj) == 0

		if !validW1 || !validCj {
			return ErrInvalidRangeProof
		}

	case ei == 1 && proofPair.J == 2:
		if proofPair.W1 != nil || proofPair.R1 != nil ||
			proofPair.W2 == nil || proofPair.R2 == nil {
			return ErrInvalidRangeProof
		}

		// Check if l <= w2 <= 2*l.
		validW2 := lower.Cmp(proofPair.W2) <= 0 &&
			proofPair.W2.Cmp(upper) < 0

		cc2 := new(big.Int).Mul(p.C, ctxtPair.C2)
		cc2.Mod(cc2, p.PPK.NSquared)

		cj, err := paillier.EncryptWithNonce(
			p.PPK, proofPair.R2, proofPair.W2.Bytes(),
		)
		if err != nil {
			return err
		}

		validCj := cc2.Cmp(cj) == 0

		if !validW2 || !validCj {
			return ErrInvalidRangeProof
		}

	default:
		return ErrInvalidRangeProof
	}

	return nil
}

func randBitSlice(n int) (BitSlice, error) {
	nbytes := (n + 7) / 8
	b := make([]byte, nbytes)
	_, err := io.ReadFull(rand.Reader, b)
	return BitSlice(b), err
}
