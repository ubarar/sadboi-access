package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/ubarar/sadboi-access/redirect"
	"github.com/ubarar/sadboi-access/session"
	"github.com/ubarar/sadboi-access/verify"
)

var authPage []byte

func init() {
	f, err := os.Open("../web/index.html")
	if err != nil {
		panic(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	authPage = data
}

func NewProxy(targerHost string) (*httputil.ReverseProxy, error) {
	url, err := url.Parse(targerHost)
	if err != nil {
		return nil, err
	}

	return httputil.NewSingleHostReverseProxy(url), nil
}

func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// request is returning after a redirect. Check the form for credentials and verify them
		if !session.IsRequestAuthorized(r) && r.URL.String() == "/redirect" && r.Method == http.MethodPost {
			if !verify.Verify(r) {
				fmt.Fprintf(w, "The request is not verified")
				return
			}

			email, err := verify.GetEmail(r)
			if err != nil {
				fmt.Fprintf(w, "Could not find email with error: %v", err)
				return
			}

			// auth is successful. Now we fetch original destination and send the user
			// there.

			finalURL, ok := redirect.GetRedirectNone(r)
			if !ok {
				finalURL = "/"
			}

			session.CreateNewSession(w, email)

			http.Redirect(w, r, finalURL, http.StatusSeeOther)

			return

			// unauthorized request, serve them a login page
		} else if !session.IsRequestAuthorized(r) {

			if r.URL.String() == "/favicon.ico" {
				fmt.Println("not setting cookie becuase favicon")
				return
			}

			redirect.SaveRedirectNonce(w, redirect.GenerateNonce(), *r.URL)
			w.Write(authPage)

			// authorized session, let it be proxied
		} else {
			proxy.ServeHTTP(w, r)
		}
	}
}

func main() {
	proxy, err := NewProxy("http://localhost:8090")
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", ProxyRequestHandler(proxy))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
