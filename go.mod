module github.com/cloudflare/dnssec-serializing-server-go

// +heroku goVersion go1.19
// +scalingo goVersion go1.19
go 1.14

require github.com/miekg/dns v1.1.50

replace github.com/miekg/dns v1.1.50 => github.com/iowaguy/dns v1.1.50-serial.6
