package tpec

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

type Comm = Uint256

type Nonce = Uint256

var ErrInvalidCommitment = errors.New("invalid commitment")

func Commit(data []byte) (Comm, Nonce, error) {
	var nonce Nonce
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return Comm{}, nonce, err
	}

	return commit(data, &nonce), nonce, nil
}

func (c *Comm) Verify(data []byte, nonce *Nonce) error {
	if *c == commit(data, nonce) {
		return nil
	}

	return ErrInvalidCommitment
}

func commit(data []byte, nonce *Nonce) Comm {
	h := sha256.New()
	h.Write(data)
	h.Write(nonce[:])

	var comm Comm
	copy(comm[:], h.Sum(nil))
	return comm
}
