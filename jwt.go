package got

import (
	"crypto"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"got/jws"
	"hash"
	"strings"
	"time"
)

type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}

type JWTHeader struct {
	Algorithm jws.SigningAlgorithm `json:"alg,omitempty"`
	// RECOMMENDED to be uppercase JWT
	Type string `json:"typ,omitempty"`
	// NOT RECOMMENDED to be used when there's no nested or encrypted jwt
	// MUST be used if nested or encrypted
	// RECOMMENDED to be uppercase JWT
	ContentType string `json:"cty,omitempty"`
	// Present on JWEs
	Encryption string `json:"enc,omitempty"`
}

// String() is used to debug-print the struct to human-readable text.
//
// Returns a string-representation of the struct.
func (h JWTHeader) String() string {
	return fmt.Sprintf(`JWTHeader{Type: "%s", ContentType: "%s", Algorithm: "%s"}`, h.Type, h.ContentType, h.Algorithm)
}

// Encoded() encodes the JWTHeader to base64 and returns it.
//
// Empty fields in the header will be omitted when base64 encoding the JSON-representation.
func (h JWTHeader) Encoded() (string, error) {
	jsonBytes, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding.EncodeToString(jsonBytes)

	return enc, nil
}

type JWTPayload struct {
	Issuer     string         `json:"iss,omitempty"`
	Subject    string         `json:"sub,omitempty"`
	Audience   []string       `json:"aud,omitempty"`
	Expiration int64          `json:"exp,omitempty"`
	NotBefore  int64          `json:"nbf,omitempty"`
	IssuedAt   int64          `json:"iat,omitempty"`
	ID         string         `json:"jti,omitempty"`
	Custom     map[string]any `json:"-"`
}

// Taken from:
// https://stackoverflow.com/questions/49901287/embed-mapstringstring-in-go-json-marshaling-without-extra-json-property-inlin
func (p JWTPayload) MarshalJSON() ([]byte, error) {
	type Payload JWTPayload
	b, err := json.Marshal(Payload(p))
	if err != nil {
		return nil, err
	}

	var m map[string]json.RawMessage
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	for k, v := range p.Custom {
		// Don't allow overriding struct fields
		if _, ok := m[k]; ok {
			continue
		}
		b, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = b
	}

	return json.Marshal(m)
}

func (p *JWTPayload) UnmarshalJSON(data []byte) error {
	type Payload JWTPayload
	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	var payload Payload
	err = json.Unmarshal(b, &payload)
	if err != nil {
		return err
	}

	for k, v := range raw {
		switch k {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
		default:
			if payload.Custom == nil {
				payload.Custom = make(map[string]any)
			}
			payload.Custom[k] = v
		}
	}

	*p = JWTPayload(payload)

	return err
}

func (p JWTPayload) String() string {
	return fmt.Sprintf(
		`JWTPayload{Issuer: "%s", Subject: "%s", Audience: %v, Expiration: %d, NotBefore: %d, IssuedAt: %d, ID: "%s", Custom: %v}`,
		p.Issuer,
		p.Subject,
		p.Audience,
		p.Expiration,
		p.NotBefore,
		p.IssuedAt,
		p.ID,
		p.Custom,
	)
}

func (p JWTPayload) Encoded() (string, error) {
	jsonBytes, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding.EncodeToString(jsonBytes)
	return enc, nil
}

type JWTSignature []byte

func (s JWTSignature) String() string {
	return fmt.Sprintf("JWTSignature{%v}", []byte(s))
}

func (s JWTSignature) Encoded() string {
	return base64.RawURLEncoding.EncodeToString(s)
}

type Jwt struct {
	header     JWTHeader
	payload    JWTPayload
	signature  JWTSignature
	signingKey []byte
}

func (j *Jwt) SetIssuer(iss string) *Jwt {
	j.payload.Issuer = iss
	return j
}

func (j *Jwt) SetSubject(sub string) *Jwt {
	j.payload.Subject = sub
	return j
}

func (j *Jwt) SetAudience(aud ...string) *Jwt {
	j.payload.Audience = aud
	return j
}

func (j *Jwt) SetExpiration(exp time.Time) *Jwt {
	j.payload.Expiration = exp.Unix()
	return j
}

func (j *Jwt) SetNotBefore(nbf time.Time) *Jwt {
	j.payload.NotBefore = nbf.Unix()
	return j
}

func (j *Jwt) SetIssuedAt(iat time.Time) *Jwt {
	j.payload.IssuedAt = iat.Unix()
	return j
}

func (j *Jwt) SetID(id string) *Jwt {
	j.payload.ID = id
	return j
}

// This function CANNOT set the [Registered Claim Names]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
// only Public and Private claims
func (j *Jwt) SetCustomClaim(name string, value any) *Jwt {
	j.payload.Custom[name] = value
	return j
}

// Computes the signature and returns the final base64 encoded Json Web Token as a string
func (j Jwt) Sign() (string, error) {
	hEnc, err := j.header.Encoded()
	if err != nil {
		return "", err
	}

	pEnc, err := j.payload.Encoded()
	if err != nil {
		return "", err
	}

	signature, err := computeSignature(j.header.Algorithm, j.signingKey, hEnc, pEnc)
	if err != nil {
		return "", err
	}
	j.signature = signature

	sEnc := j.signature.Encoded()

	return strings.Join([]string{hEnc, pEnc, sEnc}, "."), nil
}

var privKey *rsa.PrivateKey

// CreateJWS() creates a JWS JWT.
// TODO: change this to accept a SigningKey type which is just an interface{}
// And then we can type check it during runtime
func CreateJWS(a jws.SigningAlgorithm, signingKey []byte) *Jwt {
	var jwt Jwt
	var h JWTHeader

	privKey, _ = rsa.GenerateKey(cryptorand.Reader, 2048)

	h.Type = "JWT"
	h.Algorithm = a

	// TODO: something something delete this and something something do the same for elliptic curves and PSS
	fmt.Println(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&privKey.PublicKey)))
	fmt.Println(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privKey)))

	jwt.signingKey = signingKey
	jwt.header = h
	jwt.payload.IssuedAt = time.Now().Unix()
	jwt.payload.Custom = make(map[string]any)

	return &jwt
}

func computeSignature(algorithm jws.SigningAlgorithm, signingKey []byte, encodedHeader, encodedPayload string) (signature []byte, err error) {
	switch algorithm {
	case jws.None:
		return nil, nil
	case jws.HS256, jws.HS384, jws.HS512:
		var h hash.Hash
		if algorithm == jws.HS256 {
			h = hmac.New(sha256.New, signingKey)
		} else if algorithm == jws.HS384 {
			h = hmac.New(sha512.New384, signingKey)
		} else if algorithm == jws.HS512 {
			h = hmac.New(sha512.New, signingKey)
		}

		h.Write([]byte(encodedHeader))
		h.Write([]byte{'.'})
		h.Write([]byte(encodedPayload))

		hmacsha := h.Sum(nil)

		signature = hmacsha
	case jws.RS256, jws.RS384, jws.RS512:
		// TODO: key of size 2048 bits or larger MUST be used here.
		var h []byte
		if algorithm == jws.RS256 {
			sha := sha256.New()
			sha.Write([]byte(encodedHeader))
			sha.Write([]byte{'.'})
			sha.Write([]byte(encodedPayload))
			hashed := sha.Sum(nil)

			h, err = rsa.SignPKCS1v15(nil, privKey, crypto.SHA256, hashed)
			if err != nil {
				return nil, err
			}
		} else if algorithm == jws.RS384 {
			sha := sha512.New384()
			sha.Write([]byte(encodedHeader))
			sha.Write([]byte{'.'})
			sha.Write([]byte(encodedPayload))
			hashed := sha.Sum(nil)

			h, err = rsa.SignPKCS1v15(nil, privKey, crypto.SHA384, hashed)
			if err != nil {
				return nil, err
			}
		} else if algorithm == jws.RS512 {
			sha := sha512.New()
			sha.Write([]byte(encodedHeader))
			sha.Write([]byte{'.'})
			sha.Write([]byte(encodedPayload))
			hashed := sha.Sum(nil)

			h, err = rsa.SignPKCS1v15(nil, privKey, crypto.SHA512, hashed)
			if err != nil {
				return nil, err
			}
		}

		signature = h
	case jws.PS256, jws.PS384, jws.PS512:
		// TODO: This is incorrect. We get an invalid signature when verifying.
		var h []byte

		if algorithm == jws.PS256 {
			sha := sha256.New()
			sha.Write([]byte(encodedHeader))
			sha.Write([]byte{'.'})
			sha.Write([]byte(encodedPayload))
			hashed := sha.Sum(nil)

			h, err = rsa.SignPSS(cryptorand.Reader, privKey, crypto.SHA256, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256})
		} else if algorithm == jws.PS384 {
			sha := sha512.New384()
			sha.Write([]byte(encodedHeader))
			sha.Write([]byte{'.'})
			sha.Write([]byte(encodedPayload))
			hashed := sha.Sum(nil)

			h, err = rsa.SignPSS(cryptorand.Reader, privKey, crypto.SHA384, hashed, nil)
		} else if algorithm == jws.PS512 {
			sha := sha512.New()
			sha.Write([]byte(encodedHeader))
			sha.Write([]byte{'.'})
			sha.Write([]byte(encodedPayload))
			hashed := sha.Sum(nil)

			h, err = rsa.SignPSS(cryptorand.Reader, privKey, crypto.SHA512, hashed, nil)
		}

		signature = h
	case jws.ES256, jws.ES384, jws.ES512:
		panic("TODO: ESXXX algo not supported")
	}

	return signature, err
}

// https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
func Verify(s string, signingKey []byte) error {
	parts := strings.Split(s, ".")
	// 1. Verify that the JWT contains at least one period (".") character
	if len(parts) <= 1 {
		return ValidationError("JWT doesn't contain any periods.")
	}

	// 2. Let the Encoded JOSE Header be the portion of the JWT before the first period ('.') character.
	encodedHeader := parts[0]

	// 3. Base64url decode the Encoded JOSE Header following the
	//    restriction that no line breaks, whitespace, or other additional
	//    characters have been used.
	header, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return err
	}

	// 4. Verify that the resulting octet sequence is a UTF-8-encoded
	//    representation of a completely valid JSON object conforming to
	//    RFC 7159 [RFC7159]; let the JOSE Header be this JSON object.
	if !json.Valid(header) {
		return ValidationError("JWT Header is not valid JSON")
	}

	// 5. Verify that the resulting JOSE Header includes only parameters
	//    and values whose syntax and semantics are both understood and
	//    supported or that are specified as being ignored when not
	//    understood
	var jose JWTHeader
	err = json.Unmarshal(header, &jose)
	if err != nil {
		return err
	}
	if jose.Algorithm.String() == "" {
		return ValidationError("Algorithm is Missing")
	}

	// 6. Determine whether the JWT is a JWS or a JWE
	if jose.Encryption == "" {
		// This is a JWS
		// 7. Validate JWS
		_, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return err
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return err
		}

		computedSignature, err := computeSignature(jose.Algorithm, signingKey, parts[0], parts[1])
		if err != nil {
			return err
		}

		// The comparison of the computed HMAC value to the JWS Signature MUST be done in a constant-time manner to
		// thwart timing attacks.
		// https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
		if subtle.ConstantTimeCompare(computedSignature, signature) == 0 {
			return ValidationError(fmt.Sprintf("Invalid signature:\nExpected: %v\nGot: %v", signature, computedSignature))
		}
	} else {
		// This is a JWE
		// 7. Validate JWE
		// TODO:
	}

	return nil
}

// TODO: Add support for JWE JWTs
// JWEs have their own set of algorithms that we must implement to encrypt and decrypt the JWE payload
