package redirect

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"time"
)

const cookieName string = "x-sadboi-access-redirect-nonce"

const sessionLength time.Duration = 1 * time.Minute

var redirects map[string]url.URL = map[string]url.URL{}

func GenerateNonce() string {
	return uuid.NewString()
}

func SaveRedirectNonce(w http.ResponseWriter, nonce string, url url.URL) {
	redirects[nonce] = url

	fmt.Printf("setting cookie %s %v\n", nonce, url)

	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: nonce, Expires: time.Now().Add(time.Minute), Path: "/"})
}

func GetRedirectNone(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		fmt.Println(err)
		return "/notfound", false
	}

	url, ok := redirects[cookie.Value]

	if !ok {
		fmt.Printf("Could not find in redirects: %s\n", cookie.Value)
		return "/notfound2", false
	}

	fmt.Printf("found %v\n", url.String())

	return url.String(), true
}

func GetEmailFromRedirect(r *http.Request, jwtSecret string) (string, error) {
	return "", nil
}
