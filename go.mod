module github.com/cloudflare/dnssec-serializing-server-go

// +heroku goVersion go1.19
// +scalingo goVersion go1.19
go 1.14

require (
	github.com/allegro/bigcache/v3 v3.1.0
	github.com/miekg/dns v1.1.50
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
)

replace github.com/miekg/dns v1.1.50 => github.com/iowaguy/dns v1.1.50-restructure.4
