package jws

import (
	"errors"
	"fmt"
)

type SigningAlgorithm struct{ a uint }

var (
	None  = SigningAlgorithm{0}
	HS256 = SigningAlgorithm{1}
	HS384 = SigningAlgorithm{2}
	HS512 = SigningAlgorithm{3}
	PS256 = SigningAlgorithm{4}
	PS384 = SigningAlgorithm{5}
	PS512 = SigningAlgorithm{6}
	RS256 = SigningAlgorithm{7}
	RS384 = SigningAlgorithm{8}
	RS512 = SigningAlgorithm{9}
	ES256 = SigningAlgorithm{10}
	ES384 = SigningAlgorithm{11}
	ES512 = SigningAlgorithm{12}
	EdDSA = SigningAlgorithm{13}
)

// TODO: comparisons should be case insensitive I think
// NOTE: These are the algorithms for digitally signing the JWS.
//
// JWE has its own set of algorithms to be used.
func (algo SigningAlgorithm) String() string {
	switch algo.a {
	case 0:
		return "none"
	case 1:
		return "HS256"
	case 2:
		return "HS384"
	case 3:
		return "HS512"
	case 4:
		return "PS256"
	case 5:
		return "PS384"
	case 6:
		return "PS512"
	case 7:
		return "RS256"
	case 8:
		return "RS384"
	case 9:
		return "RS512"
	case 10:
		return "ES256"
	case 11:
		return "ES384"
	case 12:
		return "ES512"
	case 13:
		return "EdDSA"
	}

	panic("Invalid algorithm")
}

func stringToAlgorithm(data string) (SigningAlgorithm, error) {
	switch data {
	case "none":
		return None, nil
	case "HS256":
		return HS256, nil
	case "HS384":
		return HS384, nil
	case "HS512":
		return HS512, nil
	case "PS256":
		return PS256, nil
	case "PS384":
		return PS384, nil
	case "PS512":
		return PS512, nil
	case "RS256":
		return RS256, nil
	case "RS384":
		return RS384, nil
	case "RS512":
		return RS512, nil
	case "ES256":
		return ES256, nil
	case "ES384":
		return ES384, nil
	case "ES512":
		return ES512, nil
	case "EdDSA":
		return EdDSA, nil
	}

	return None, errors.New(fmt.Sprintf("Invalid Algorithm: %s", data))
}

func (algo SigningAlgorithm) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, algo.String())), nil
}

func (algo *SigningAlgorithm) UnmarshalJSON(data []byte) error {
	dataStr := string(data)
	if dataStr == `""` || len(dataStr) <= 1 {
		return errors.New(fmt.Sprintf("Invalid Algorithm: %s", dataStr))
	}

	a, err := stringToAlgorithm(dataStr[1 : len(dataStr)-1])
	*algo = a

	return err
}
