package totp

import (
	"encoding/base32"
	"fmt"
	"net/url"

	"github.com/skip2/go-qrcode"
)

const (
	scheme string = "otpauth"
	host   string = "totp"
)

var b32 *base32.Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type uri struct {
	url *url.URL
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
