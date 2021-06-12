package totp

import (
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"math"
	"time"
)

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
