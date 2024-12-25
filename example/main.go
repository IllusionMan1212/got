package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"got"
	"got/jws"
	"math/big"
	"time"
)

func main() {
	symmetricKey := []byte("mysecretmysecretmysecretmysecretmysecretmysecretmysecretmysecret")
	rsaKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	edPubKey, edPrivKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Symmetric Key: %s\n", symmetricKey)

	fmt.Printf("RSA PublicKey: %v\n", base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)))
	fmt.Printf("RSA PrivateKey: %v\n", base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(rsaKey)))
	s, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	ca := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Docker, Inc."},
		},
		NotBefore: time.Now().Add(-time.Hour * 24 * 365),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
	}
	cert, err := x509.CreateCertificate(cryptorand.Reader, &ca, &ca, &ecKey.PublicKey, ecKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("EC PrivateKey: %v\n", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: s})))
	fmt.Printf("EC Cert: %v\n", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})))

	s2, err := x509.MarshalPKCS8PrivateKey(edPrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("ED25519 PrivateKey: %v\n", base64.RawURLEncoding.EncodeToString(s2))

	jwt, err := got.
		CreateJWS(jws.EdDSA, edPrivKey).
		SetExpiration(time.Now().Add(time.Minute*5)).
		SetCustomClaim("MyCustomClaim", "IsThis").
		SetIssuer("Auth Server™").
		Sign()

	if err != nil {
		fmt.Println(err)
		return
	}

	// TODO: we'll need a func to parse a jwt (jws or jwe) from a string and return us a JWS or JWE object
	// that we can then verify??
	// The need for a parsing func is so we can extract information from the JWT's payload
	// I think we'll return a map[string]any as the payload from the parsing func

	err = got.Verify(jwt, edPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(jwt)
}
