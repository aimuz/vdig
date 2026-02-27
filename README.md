# vdig

A dig-compatible DNS lookup tool written in Go, supporting multiple transport protocols.

## Features

- **dig-compatible** output format and command-line interface
- **Multi-protocol**: UDP, TCP, DoT (DNS over TLS), DoH (DNS over HTTPS), DoQ (DNS over QUIC)
- **RFC 1035 §5.1** compliant name escaping (handles labels containing dots)
- All DNS record types supported via [miekg/dns](https://github.com/miekg/dns)

## Install

```bash
go install go.aimuz.me/vdig@latest
```

## Usage

```bash
# Basic lookup
vdig google.com
vdig google.com AAAA
vdig google.com MX

# Specify server
vdig @8.8.8.8 google.com

# DNS over HTTPS
vdig @https://1.1.1.1/dns-query google.com

# DNS over TLS
vdig @tls://1.1.1.1 google.com

# DNS over QUIC
vdig @quic://dns.adguard.com google.com

# Reverse lookup
vdig -x 8.8.8.8

# Short output
vdig google.com +short

# Force TCP
vdig google.com +tcp

# IPv4/IPv6 only
vdig -4 google.com
vdig -6 google.com AAAA

# Custom port
vdig @1.1.1.1 -p 5353 google.com

# Display control (dig-compatible)
vdig google.com +noall +answer
```

## License

MIT
