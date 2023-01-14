package verify

import (
	"context"
	"crypto/rsa"
	"net/http"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

const googleJwkUrl string = "https://www.googleapis.com/oauth2/v3/certs"

var googlePublicKeySet jwk.Set

// will load public keys that verify JWTs from google
// guide : https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
func init() {
	set, err := jwk.Fetch(context.Background(), googleJwkUrl)

	if err != nil {
		panic(fmt.Sprintf("Could not load google certs : %v", err))
	}

	googlePublicKeySet = set
}

// Is the request valid? Check that the CSRF tokens match and that the JWT provided is
// signed correctly
func Verify(r *http.Request) bool {
	// check if we can get the token out, this checks for JWT sign
	_, err := getTokenFromRequest(r)
	if err != nil {
		return false
	}

	// check that CSRF matches
	csrfCookie, err := r.Cookie("g_csrf_token")
	if err != nil || csrfCookie == nil {
		return false
	}

	csrfForm, ok := r.Form["g_csrf_token"]
	if !ok {
		return false
	}

	return csrfCookie.Value == csrfForm[0]
}

func getTokenFromRequest(r *http.Request) (*jwt.Token, error) {
	if r == nil {
		return nil, errors.New("request is nil")
	}

	err := r.ParseForm()
	if err != nil {
		return nil, err
	}

	credential, ok := r.Form["credential"]
	if !ok || len(credential) < 1 {
		return nil, errors.New("No request in form")
	}

	return jwt.Parse(credential[0], jwtKeyFunc)
}

func GetEmail(r *http.Request) (string, error) {
	token, err := getTokenFromRequest(r)
	if err != nil {
		return "", err
	}

	email, ok := token.Claims.(jwt.MapClaims)["email"]
	if !ok {
		return "", errors.New("email not in claim")
	}

	return email.(string), nil
}

func jwtKeyFunc(token *jwt.Token) (interface{}, error) {

	keyID, ok := token.Header["kid"].(string)

	if !ok {
		return nil, errors.New("JWT header does not contain kid")
	}

	key, ok := googlePublicKeySet.LookupKeyID(keyID)
	if !ok {
		return nil, fmt.Errorf("Could not find kid %s", keyID)
	}

	// this is a shortcut because I know Google signs with RSA, but you could
	// have an empty interface here and it should work fine. That would be useful
	// if you didn't know the algorithm of the key
	rsaKey := rsa.PublicKey{}

	err := key.Raw(&rsaKey)

	if err != nil {
		return nil, err
	}

	// incredibly important because deep inside the verify functions - this expects a
	// pointer to a key, not the key itself
	return &rsaKey, nil
}
