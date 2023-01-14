package session

import (
	"testing"
	"time"
)

func TestSessionIsAuthorized(t *testing.T) {
	var tests = []struct {
		name      string
		sessionID string
		sessions  map[string]Session
		want      bool
	}{
		{
			"Happy path",
			"test",
			map[string]Session{
				"test": {
					email:      "test",
					validUntil: time.Now().Add(time.Minute),
				},
			},
			true,
		},
		{
			"Expired Session",
			"test",
			map[string]Session{
				"test": {
					email:      "test",
					validUntil: time.Now().Add(-1 * time.Minute),
				},
			},
			false,
		},
		{
			"Non-existent session",
			"test",
			map[string]Session{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isSessionAuthorized(tt.sessionID, tt.sessions) != tt.want {
				t.Errorf("wanted %v", tt.want)
			}
		})
	}
}
