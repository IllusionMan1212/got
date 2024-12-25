package main

import (
	"fmt"
	"got"
	"got/jws"
	"time"
)

func main() {
	signingKey := []byte("mysecret")

	jwt, err := got.
		CreateJWS(jws.PS256, signingKey).
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

	err = got.Verify(jwt, signingKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(jwt)
}
