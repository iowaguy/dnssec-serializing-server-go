module github.com/cloudflare/dnssec-serializing-server-go

// +heroku goVersion go1.19
// +scalingo goVersion go1.19
go 1.14

require (
	github.com/allegro/bigcache/v3 v3.1.0 // indirect
	github.com/cisco/go-hpke v0.0.0-20221026214622-55155e0d96c6 // indirect
	github.com/cloudflare/odoh-go v1.0.0 // indirect
	github.com/miekg/dns v1.1.50
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

//replace github.com/miekg/dns v1.1.50 => github.com/iowaguy/dns v1.1.50-serial.6
replace github.com/miekg/dns v1.1.50 => ../dns
