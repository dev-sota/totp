package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"

	"github.com/skip2/go-qrcode"
)

const (
	scheme string = "otpauth"
	host   string = "totp"
)

var b32 *base32.Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type Label struct {
	Issuer      string // required
	AccountName string // required
	Secret      []byte // optional
	SecretSize  uint   // optional default: 20
}

type uri struct {
	url *url.URL
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

func (u uri) String() string {
	return u.url.String()
}

func (u uri) Secret() string {
	return u.url.Query().Get("secret")
}

func (u uri) Image(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("size is too small")
	}
	return qrcode.Encode(u.String(), qrcode.Medium, size)
}

func (u uri) WriteFile(size int, fileName string) error {
	if size <= 0 {
		return fmt.Errorf("size is too small")
	}
	return qrcode.WriteFile(u.url.String(), qrcode.Medium, size, fmt.Sprintf("%s.png", fileName))
}
