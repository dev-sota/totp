package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
)

func (a Algorithm) String() string {
	return string(a)
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case SHA1:
		return sha1.New()
	case SHA256:
		return sha256.New()
	default:
		return sha1.New()
	}
}
