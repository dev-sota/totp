package totp

type calculator struct {
	algorithm Algorithm
	digits    int
	period    int
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

// func NewWithOpts(digits, period int, algorithm Algorithm) Calculator {
// 	return &calculator{
// 		algorithm: algorithm,
// 		digits:    digits,
// 		period:    period,
// 	}
// }
