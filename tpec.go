package tpec

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/roasbeef/go-go-gadget-paillier"
)

var (
	ErrInvalidPrimalityProof = errors.New(
		"invalid paillier public key primality proof",
	)
)

var (
	keyGenPhase1Msg = []byte("2P-ECDSA-KEYGEN-1")
	keyGenPhase2Msg = []byte("2P-ECDSA-KEYGEN-2")

	signPhase1Msg = []byte("2P-ECDSA-SIGN-1")
	signPhase2Msg = []byte("2P-ECDSA-SIGN-2")
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type Uint256 [32]byte

type Config struct {
	Q        *big.Int
	Q3       *big.Int
	QSquared *big.Int

	NPaillierBits  int
	NthRootSecBits int
	RangeSecBits   int
}

type Party1 struct {
	cfg *Config

	// Keygen phase 1
	x1      *eckey.SecretKey
	X1      *eckey.PublicKey
	X1PoK   *DLogPoK
	X1Nonce Nonce

	// Keygen phase 3
	X2        *eckey.PublicKey
	PSK       *paillier.PrivateKey
	CKey      *big.Int
	CKeyNonce *big.Int
	RPProver  *RangeProofProver

	// Keygen phase 5
	ABComm     Comm
	Alpha      *big.Int
	AlphaPK    *eckey.CompressedPublicKey
	AlphaNonce Nonce

	//Keygen phase 7
	Q *eckey.PublicKey
}

type Party1PrivateKey struct {
	cfg       *Config
	PSK       *paillier.PrivateKey
	X1SK      *eckey.SecretKey
	PublicKey *btcec.PublicKey
}

func NewParty1(cfg *Config) *Party1 {
	return &Party1{
		cfg: cfg,
	}
}

type Party2 struct {
	cfg *Config

	// Keygen phase 2
	X1PoKComm  Comm
	x2         *eckey.SecretKey
	X2         *eckey.PublicKey
	X2PoK      *DLogPoK
	RPVerifier *RangeProofVerifier

	// Keygen phase 4
	X1      *eckey.PublicKey
	PPK     *paillier.PublicKey
	CKey    *big.Int
	CPrime  *big.Int
	A       *big.Int
	B       *big.Int
	ABNonce Nonce

	// Keygen phase 6
	AlphaComm Comm

	// Keygen phase 8
	Q *eckey.PublicKey
}

type Party2PrivateKey struct {
	cfg       *Config
	PPK       *paillier.PublicKey
	CKey      *big.Int
	X2SK      *eckey.SecretKey
	PublicKey *btcec.PublicKey
}

func NewParty2(cfg *Config) *Party2 {
	return &Party2{
		cfg: cfg,
	}
}

func NewPrivKey(modulus *big.Int) (*eckey.SecretKey, error) {
	x, err := rand.Int(rand.Reader, modulus)
	if err != nil {
		return nil, err
	}

	return eckey.NewSecretKeyInt(x)
}
