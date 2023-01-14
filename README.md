# About

Toy project - an open source alternative(-ish) to Cloudflare Access.

- Implemented as a reverse proxy
- Storing State in memory, unsuitable for long-running sessions

# How to run

`go run cmd/main.go` - will require prior setup in GCP. and you _must_ add your client ID in `web/index.html`