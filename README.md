# TOTP Authenticator

Generate example
```
t := totp.New()

uri, err := t.Generate(totp.Label{
  Issuer:      "Issuer.com",
  AccountName: "test@example.com",
})

secret := uri.Secret()             // UY346VGBYX4ELCZPCKHGKDFM6FVJEGLX
str := uri.String()                // otpauth://totp/Issuer.com:test@example.com?algorithm=SHA1&digits=6&issuer=Issuer.com&period=30&secret=UY346VGBYX4ELCZPCKHGKDFM6FVJEGLX
image, err = uri.Image(256)        // Convert []byte
err = uri.WriteFile(256, "qrcode") // qrcode.png
```

Validate Code
```
ok := t.Validate(123456, "UY346VGBYX4ELCZPCKHGKDFM6FVJEGLX")
```
