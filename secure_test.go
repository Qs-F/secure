package secure

import (
	"testing"
)

func TestNewPrivKey(t *testing.T) {
	stdout := Stdout{}
	SetLog(stdout)
	priv, err := NewPrivKey()
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(priv)
	enc, err := EncryptStringToBPubKey(NewPubKey(priv), "string")
	t.Log(enc)
	dec, err := DecryptBytePrivKey(priv, enc)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(string(dec))
}

func TestNewPrivPem(t *testing.T) {
	SetLog(Stdout{})
	priv, err := NewPrivKey()
	if err != nil {
		t.Error(err.Error())
	}
	pem := NewPrivPem(priv)
	t.Log(BToS(pem))
	rPriv, err := RestorePrivKey(pem)
	if err != nil {
		t.Error(err.Error())
	}
	rPem := NewPrivPem(rPriv)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(BToS(rPem))
}

func BenchmarkNewPrivKey(b *testing.B) {
	NewPrivKey()
}

func TestRestorePrivPem(t *testing.T) {
	SetLog(Stdout{})
	priv, err := NewPrivKey()
	if err != nil {
		t.Error(err.Error())
	}
	pem := NewPrivPem(priv)
	t.Log(BToS(pem))
	rPriv, err := RestorePrivKey(pem)
	if err != nil {
		t.Error(err.Error())
	}
	rPem := NewPrivPem(rPriv)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(BToS(rPem))
}

func TestRestorePrivKey(t *testing.T) {
	SetLog(Stdout{})
	priv, err := NewPrivKey()
	if err != nil {
		t.Error(err.Error())
	}
	pem := NewPrivPem(priv)
	t.Log(BToS(pem))
	rPriv, err := RestorePrivKey(pem)
	if err != nil {
		t.Error(err.Error())
	}
	rPem := NewPrivPem(rPriv)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(BToS(rPem))
}

func TestDecryptBytePrivKey(t *testing.T) {
	SetLog(Stdout{})
	priv, err := NewPrivKey()
	if err != nil {
		t.Error(err.Error())
	}
	pub := NewPubKey(priv)
	b, err := EncryptStringToBPubKey(pub, "string")
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(BToS(EncodeBase64(b)))
	s, err := DecryptBytePrivKey(priv, b)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(BToS(s))
}

func TestNewPubPem(t *testing.T) {
	SetLog(Stdout{})
	privKey, err := NewPrivKey()
	if err != nil {
		t.Error(err.Error())
	}
	pubKey := NewPubKey(privKey)
	b, err := EncryptStringPubKey(pubKey, "string!")
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(b)
	pubPem, err := NewPubPem(pubKey)
	if err != nil {
		t.Error(err.Error)
	}
	t.Log(BToS(pubPem))
	rPubKey, err := RestorePubKey(pubPem)
	rb, err := EncryptStringPubKey(rPubKey, "string!")
	if err != nil {
		t.Error(err.Error())
	}
	db, err := DecryptStringPrivKey(privKey, rb)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(db)
}
