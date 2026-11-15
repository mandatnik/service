package setup

import (
	"crypto/rand"
	"io"
	"math/big"
)

func randReader() io.Reader { return rand.Reader }

func randInt(limit *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, limit)
}
