package session

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

const cookieName string = "x-sadboi-access"

const sessionLength time.Duration = 1 * time.Minute

type Session struct {
	email      string
	validUntil time.Time
}

// maps sessionID to email
var sessions map[string]Session = map[string]Session{}

func GenerateSession() string {
	return uuid.NewString()
}

func CreateNewSession(w http.ResponseWriter, email string) {
	sessionID, validUntil := GenerateSession(), time.Now().Add(sessionLength)

	sessions[sessionID] = Session{email, validUntil}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sessionID, Expires: validUntil, Path: "/"})
}

// if the request has a valid session and it isn't expired return true
func IsRequestAuthorized(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}

	return isSessionAuthorized(cookie.Value, sessions)
}

func isSessionAuthorized(sessionID string, sessions map[string]Session) bool {
	session, ok := sessions[sessionID]

	// the sessionID doesn't map to a session
	if !ok {
		return false
	}

	if time.Now().After(session.validUntil) {
		return false
	}

	return true
}
