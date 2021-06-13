package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"
)

type calculator struct {
	algorithm Algorithm
	digits    int
	period    int
}

type Label struct {
	Issuer      string // required
	AccountName string // required
	Secret      []byte // optional
	SecretSize  uint   // optional default: 20
}

type Calculator interface {
	Generate(l Label) (*uri, error)
	Validate(pin int, secret string) bool
}

func New() Calculator {
	return &calculator{
		algorithm: SHA1,
		digits:    6,
		period:    30,
	}
}

func NewWithOpts(digits, period int, algorithm Algorithm) Calculator {
	return &calculator{
		algorithm: algorithm,
		digits:    digits,
		period:    period,
	}
}

func (c calculator) Generate(l Label) (*uri, error) {
	if l.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	if l.AccountName == "" {
		return nil, fmt.Errorf("accountName is required")
	}

	if l.SecretSize <= 0 {
		l.SecretSize = 20
	}

	v := url.Values{}
	if len(l.Secret) != 0 {
		v.Set("secret", b32.EncodeToString(l.Secret))
	} else {
		s := make([]byte, l.SecretSize)
		_, err := rand.Reader.Read(s)
		if err != nil {
			return nil, err
		}
		v.Set("secret", b32.EncodeToString(s))
	}
	v.Set("issuer", l.Issuer)
	v.Set("algorithm", c.algorithm.String())
	v.Set("digits", strconv.Itoa(c.digits))
	v.Set("period", strconv.Itoa(c.period))

	u := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     "/" + l.Issuer + ":" + l.AccountName,
		RawQuery: v.Encode(),
	}
	return &uri{url: &u}, nil
}

func (c calculator) Validate(pin int, secret string) bool {
	b, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return false
	}
	cnt := uint64(time.Now().Unix() / int64(c.period))
	res := hmacSha(b, cnt, c.algorithm)
	totp := truncate(res, c.digits)
	return (int(totp) == pin)
}

func truncate(hmacResult []byte, digits int) uint32 {
	offset := hmacResult[len(hmacResult)-1] & 0x0F
	binCode := binary.BigEndian.Uint32(hmacResult[offset:offset+4]) & 0x7FFFFFFF
	return binCode % uint32(math.Pow10(digits))
}

func hmacSha(secretBytes []byte, counter uint64, algorithm Algorithm) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	hm := hmac.New(algorithm.Hash, secretBytes)
	hm.Write(buf)
	return hm.Sum(nil)
}
