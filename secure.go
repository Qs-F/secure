// Copyright de-liKeR @CreatorQsF 2016

// Package secure provides functions to enhance your app security very easily.
// tech-info: rsa uses PKCS1v15. privatekey pem uses PKCS1. publickey pem uses PKIX. default rsa size is 4096. if you want to use hashing, I recommend you to use builtin bcrypt package(it is very easy to use).
package secure

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"
	"unsafe"
)

var log io.Writer

var (
	Cost    = 10
	RSASize = 4096
)

// all functions in this package have logging error structure. to use it, you have to define io.Writer interface.
// if you don't need it, please use this: SetLog(Stdout{})
func SetLog(w io.Writer) {
	log = w
}

type Stdout struct{}

func (s Stdout) Write(b []byte) (int, error) {
	os.Stdout.Write(b[:])
	return 0, nil
}

func EncodeBase64(b []byte) []byte { // encode base64
	return SToB(base64.StdEncoding.EncodeToString(b))
}

func DecodeBase64(b []byte) ([]byte, error) { // decode base64
	return func() ([]byte, error) {
		b, e := base64.StdEncoding.DecodeString(BToS(b))
		if e != nil {
			log.Write(SToB(e.Error()))
			return []byte{}, e
		}
		return b, e
	}()
}

func NewPrivKey() (*rsa.PrivateKey, error) { // issue private key
	return func() (*rsa.PrivateKey, error) {
		p, e := rsa.GenerateKey(rand.Reader, RSASize)
		if e != nil {
			log.Write(SToB(e.Error()))
			return &rsa.PrivateKey{}, e
		}
		return p, e
	}()
}

func NewPrivPem(p *rsa.PrivateKey) []byte { // issue pem(PKCS1)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(p),
	})
}

func RestorePrivKey(p []byte) (*rsa.PrivateKey, error) { // restore privatekey from pem(PKCS1)
	return func() (*rsa.PrivateKey, error) {
		block, remainB := pem.Decode(p)
		if len(remainB) > 0 {
			log.Write(remainB)
		}
		privKey, e := x509.ParsePKCS1PrivateKey(block.Bytes)
		if e != nil {
			log.Write(SToB(e.Error()))
			return &rsa.PrivateKey{}, e
		}
		return privKey, e
	}()
}

func DecryptBytePrivKey(p *rsa.PrivateKey, b []byte) ([]byte, error) {
	return func() ([]byte, error) {
		dec, e := rsa.DecryptPKCS1v15(rand.Reader, p, b)
		if e != nil {
			log.Write(SToB(e.Error()))
			return []byte{}, e
		}
		return dec, e
	}()
}

func DecryptByteToSPrivKey(p *rsa.PrivateKey, b []byte) (string, error) {
	raw, err := DecryptBytePrivKey(p, b)
	return BToS(raw), err
}

func DecryptStringPrivKey(p *rsa.PrivateKey, s string) (string, error) {
	b, err := DecodeBase64(SToB(s))
	if err != nil {
		log.Write(SToB(err.Error()))
		return "", err
	}
	raw, err := DecryptBytePrivKey(p, b)
	return BToS(raw), err
}

func DecryptStringToBPrivKey(p *rsa.PrivateKey, s string) ([]byte, error) {
	b, err := DecodeBase64(SToB(s))
	if err != nil {
		log.Write(SToB(err.Error()))
		return []byte{}, err
	}
	return DecryptBytePrivKey(p, b)
}

func DecryptBytePrivPem(p []byte, b []byte) ([]byte, error) {
	key, err := RestorePrivKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return []byte{}, err
	}
	return DecryptBytePrivKey(key, b)
}

func DecryptByteToSPrivPem(p []byte, b []byte) (string, error) {
	key, err := RestorePrivKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return "", err
	}
	raw, err := DecryptBytePrivKey(key, b)
	return BToS(raw), err
}

func DecryptStringPrivPem(p []byte, s string) (string, error) {
	key, err := RestorePrivKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return "", err
	}
	b, err := DecodeBase64(SToB(s))
	if err != nil {
		log.Write(SToB(err.Error()))
		return "", err
	}
	raw, err := DecryptBytePrivKey(key, b)
	return BToS(raw), err
}

func DecryptStringToBPrivPem(p []byte, s string) ([]byte, error) {
	key, err := RestorePrivKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return []byte{}, err
	}
	b, err := DecodeBase64(SToB(s))
	if err != nil {
		log.Write(SToB(err.Error()))
		return []byte{}, err
	}
	return DecryptBytePrivKey(key, b)
}

func NewPubKey(p *rsa.PrivateKey) *rsa.PublicKey { // issue new pubkey
	return &p.PublicKey
}

func NewPubPem(p *rsa.PublicKey) ([]byte, error) { // issue new pubkey pem in PKIX byte
	b, e := x509.MarshalPKIXPublicKey(p)
	if e != nil {
		log.Write(SToB(e.Error()))
		return []byte{}, e
	}
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: b,
	})
	return pubPem, e
}

func RestorePubKey(p []byte) (*rsa.PublicKey, error) {
	return func() (*rsa.PublicKey, error) {
		block, remainB := pem.Decode(p)
		if len(remainB) > 0 {
			log.Write(remainB)
		}
		pubKey, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			log.Write(SToB(e.Error()))
			return &rsa.PublicKey{}, e
		}
		return pubKey.(*rsa.PublicKey), e
	}()
}

func RestorePrivAndPubKey(p []byte) (*rsa.PrivateKey, *rsa.PublicKey, error) { // restore privKey and pubKey from private key pem
	return func() (*rsa.PrivateKey, *rsa.PublicKey, error) {
		privKey, e := RestorePrivKey(p)
		if e != nil {
			log.Write(SToB(e.Error()))
			return &rsa.PrivateKey{}, &rsa.PublicKey{}, e
		}
		return privKey, NewPubKey(privKey), e
	}()
}

func EncryptBytePubKey(p *rsa.PublicKey, b []byte) ([]byte, error) {
	return func() ([]byte, error) {
		raw, e := rsa.EncryptPKCS1v15(rand.Reader, p, b)
		if e != nil {
			log.Write(SToB(e.Error()))
			return []byte{}, e
		}
		return raw, e
	}()
}

func EncryptByteToSPubKey(p *rsa.PublicKey, b []byte) (string, error) {
	enc, err := EncryptBytePubKey(p, b)
	return BToS(EncodeBase64(enc)), err
}

func EncryptStringPubKey(p *rsa.PublicKey, s string) (string, error) {
	enc, err := EncryptBytePubKey(p, SToB(s))
	return BToS(EncodeBase64(enc)), err
}

func EncryptStringToBPubKey(p *rsa.PublicKey, s string) ([]byte, error) {
	return EncryptBytePubKey(p, SToB(s))
}

func EncryptBytePubPem(p []byte, b []byte) ([]byte, error) {
	key, err := RestorePubKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return []byte{}, err
	}
	return EncryptBytePubKey(key, b)
}

func EncryptByteToSPubPem(p []byte, b []byte) (string, error) {
	key, err := RestorePubKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return "", err
	}
	enc, err := EncryptBytePubKey(key, b)
	return BToS(EncodeBase64(enc)), err
}

func EncryptStringPubPem(p []byte, s string) (string, error) {
	key, err := RestorePubKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return "", err
	}
	enc, err := EncryptBytePubKey(key, SToB(s))
	return BToS(EncodeBase64(enc)), err
}

func EncryptStringToBPubPem(p []byte, s string) ([]byte, error) {
	key, err := RestorePubKey(p)
	if err != nil {
		log.Write(SToB(err.Error()))
		return []byte{}, err
	}
	return EncryptBytePubKey(key, SToB(s))
}

func EscapeString(s string) string {
	return html.EscapeString(s)
}

func UnescapeString(s string) string {
	return html.UnescapeString(s)
}

func SToB(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}

func BToS(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
