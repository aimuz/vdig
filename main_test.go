package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// ============================================================================
// parseArgs Tests
// ============================================================================

func TestParseArgsBasicDomain(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		domain  string
		qType   uint16
		server  string
		proto   string
		port    string
	}{
		{
			name:   "simple domain",
			args:   []string{"google.com"},
			domain: "google.com.",
			qType:  dns.TypeA,
			server: "",
			proto:  "udp",
			port:   "53",
		},
		{
			name:   "domain with type",
			args:   []string{"google.com", "AAAA"},
			domain: "google.com.",
			qType:  dns.TypeAAAA,
			server: "",
			proto:  "udp",
			port:   "53",
		},
		{
			name:   "domain with MX type",
			args:   []string{"google.com", "MX"},
			domain: "google.com.",
			qType:  dns.TypeMX,
			server: "",
			proto:  "udp",
			port:   "53",
		},
		{
			name:   "domain with TXT type",
			args:   []string{"google.com", "TXT"},
			domain: "google.com.",
			qType:  dns.TypeTXT,
			server: "",
			proto:  "udp",
			port:   "53",
		},
		{
			name:   "domain with class",
			args:   []string{"google.com", "CH"},
			domain: "google.com.",
			qType:  dns.TypeA,
			server: "",
			proto:  "udp",
			port:   "53",
		},
		{
			name:   "no domain defaults to root NS",
			args:   []string{},
			domain: ".",
			qType:  dns.TypeNS,
			server: "",
			proto:  "udp",
			port:   "53",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if cfg.domain != tt.domain {
				t.Errorf("parseArgs() domain = %v, want %v", cfg.domain, tt.domain)
			}
			if cfg.qType != tt.qType {
				t.Errorf("parseArgs() qType = %v, want %v", cfg.qType, tt.qType)
			}
			if cfg.server != tt.server {
				t.Errorf("parseArgs() server = %v, want %v", cfg.server, tt.server)
			}
			if cfg.proto != tt.proto {
				t.Errorf("parseArgs() proto = %v, want %v", cfg.proto, tt.proto)
			}
			if cfg.port != tt.port {
				t.Errorf("parseArgs() port = %v, want %v", cfg.port, tt.port)
			}
		})
	}
}

func TestParseArgsServer(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		server string
		proto  string
		port   string
	}{
		{
			name:   "server with @ prefix",
			args:   []string{"@8.8.8.8", "google.com"},
			server: "8.8.8.8",
			proto:  "udp",
			port:   "53",
		},
		{
			name:   "server with port",
			args:   []string{"@8.8.8.8:5353", "google.com"},
			server: "8.8.8.8",
			proto:  "udp",
			port:   "5353",
		},
		{
			name:   "server with -p flag",
			args:   []string{"@8.8.8.8", "-p", "5353", "google.com"},
			server: "8.8.8.8",
			proto:  "udp",
			port:   "5353",
		},
		{
			name:   "DoH server",
			args:   []string{"@https://1.1.1.1/dns-query", "google.com"},
			server: "1.1.1.1/dns-query",
			proto:  "https",
			port:   "53",
		},
		{
			name:   "DoT server",
			args:   []string{"@tls://1.1.1.1", "google.com"},
			server: "1.1.1.1",
			proto:  "tls",
			port:   "853",
		},
		{
			name:   "DoQ server",
			args:   []string{"@quic://dns.adguard.com", "google.com"},
			server: "dns.adguard.com",
			proto:  "quic",
			port:   "853",
		},
		{
			name:   "DoT server with port",
			args:   []string{"@tls://1.1.1.1:853", "google.com"},
			server: "1.1.1.1",
			proto:  "tls",
			port:   "853",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseArgs(tt.args)
			if err != nil {
				t.Errorf("parseArgs() error = %v", err)
				return
			}
			if cfg.server != tt.server {
				t.Errorf("parseArgs() server = %v, want %v", cfg.server, tt.server)
			}
			if cfg.proto != tt.proto {
				t.Errorf("parseArgs() proto = %v, want %v", cfg.proto, tt.proto)
			}
			if cfg.port != tt.port {
				t.Errorf("parseArgs() port = %v, want %v", cfg.port, tt.port)
			}
		})
	}
}

func TestParseArgsFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		useTCP  bool
		useIPv4 bool
		useIPv6 bool
		reverse bool
	}{
		{
			name:   "+tcp flag",
			args:   []string{"google.com", "+tcp"},
			useTCP: true,
		},
		{
			name:    "-4 flag",
			args:    []string{"google.com", "-4"},
			useIPv4: true,
		},
		{
			name:    "-6 flag",
			args:    []string{"google.com", "-6"},
			useIPv6: true,
		},
		{
			name:    "-x flag for reverse lookup",
			args:    []string{"-x", "8.8.8.8"},
			reverse: true,
		},
		{
			name:   "+notcp flag",
			args:   []string{"google.com", "+tcp", "+notcp"},
			useTCP: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseArgs(tt.args)
			if err != nil {
				t.Errorf("parseArgs() error = %v", err)
				return
			}
			if cfg.useTCP != tt.useTCP {
				t.Errorf("parseArgs() useTCP = %v, want %v", cfg.useTCP, tt.useTCP)
			}
			if cfg.useIPv4 != tt.useIPv4 {
				t.Errorf("parseArgs() useIPv4 = %v, want %v", cfg.useIPv4, tt.useIPv4)
			}
			if cfg.useIPv6 != tt.useIPv6 {
				t.Errorf("parseArgs() useIPv6 = %v, want %v", cfg.useIPv6, tt.useIPv6)
			}
			if cfg.reverse != tt.reverse {
				t.Errorf("parseArgs() reverse = %v, want %v", cfg.reverse, tt.reverse)
			}
		})
	}
}

func TestParseArgsDisplayFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		short    bool
		answer   bool
		question bool
		stats    bool
	}{
		{
			name:   "+short flag",
			args:   []string{"google.com", "+short"},
			short:  true,
			answer: true,
		},
		{
			name:     "+noall +answer",
			args:     []string{"google.com", "+noall", "+answer"},
			answer:   true,
			question: false,
			stats:    false,
		},
		{
			name:     "+noquestion",
			args:     []string{"google.com", "+noquestion"},
			question: false,
			answer:   true,
			stats:    true,
		},
		{
			name:     "+all",
			args:     []string{"google.com", "+all"},
			short:    false,
			answer:   true,
			question: true,
			stats:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseArgs(tt.args)
			if err != nil {
				t.Errorf("parseArgs() error = %v", err)
				return
			}
			if cfg.display.short != tt.short {
				t.Errorf("parseArgs() short = %v, want %v", cfg.display.short, tt.short)
			}
			if cfg.display.answer != tt.answer {
				t.Errorf("parseArgs() answer = %v, want %v", cfg.display.answer, tt.answer)
			}
			if cfg.display.question != tt.question {
				t.Errorf("parseArgs() question = %v, want %v", cfg.display.question, tt.question)
			}
			if cfg.display.stats != tt.stats {
				t.Errorf("parseArgs() stats = %v, want %v", cfg.display.stats, tt.stats)
			}
		})
	}
}

func TestParseArgsErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "-p without port number",
			args:    []string{"google.com", "-p"},
			wantErr: true,
		},
		{
			name:    "-x without IP address",
			args:    []string{"-x"},
			wantErr: true,
		},
		{
			name:    "-x with invalid IP",
			args:    []string{"-x", "invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// reverseAddr Tests
// ============================================================================

func TestReverseAddrIPv4(t *testing.T) {
	tests := []struct {
		ip      string
		want    string
		wantErr bool
	}{
		{"8.8.8.8", "8.8.8.8.in-addr.arpa.", false},
		{"1.1.1.1", "1.1.1.1.in-addr.arpa.", false},
		{"192.168.1.1", "1.1.168.192.in-addr.arpa.", false},
		{"127.0.0.1", "1.0.0.127.in-addr.arpa.", false},
		{"0.0.0.0", "0.0.0.0.in-addr.arpa.", false},
		{"255.255.255.255", "255.255.255.255.in-addr.arpa.", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got, err := reverseAddr(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("reverseAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("reverseAddr(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestReverseAddrIPv6(t *testing.T) {
	tests := []struct {
		ip      string
		want    string
		wantErr bool
	}{
		// ::1
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", false},
		// 2001:4860:4860::8888 fully expanded
		{"2001:4860:4860::8888", "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa.", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got, err := reverseAddr(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("reverseAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("reverseAddr(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestReverseAddrErrors(t *testing.T) {
	tests := []struct {
		ip      string
		wantErr bool
	}{
		{"invalid", true},
		{"", true},
		{"256.256.256.256", true},
		{"google.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			_, err := reverseAddr(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("reverseAddr(%s) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// buildQuery Tests
// ============================================================================

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		qType  uint16
	}{
		{"A query", "google.com.", dns.TypeA},
		{"AAAA query", "google.com.", dns.TypeAAAA},
		{"MX query", "google.com.", dns.TypeMX},
		{"TXT query", "google.com.", dns.TypeTXT},
		{"NS query", "google.com.", dns.TypeNS},
		{"PTR query", "8.8.8.8.in-addr.arpa.", dns.TypePTR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{
				domain: tt.domain,
				qType:  tt.qType,
				qClass: dns.ClassINET,
			}
			msg := buildQuery(cfg)
			if len(msg.Question) != 1 {
				t.Errorf("buildQuery() question count = %v, want 1", len(msg.Question))
				return
			}
			q := msg.Question[0]
			if q.Name != tt.domain {
				t.Errorf("buildQuery() name = %v, want %v", q.Name, tt.domain)
			}
			if q.Qtype != tt.qType {
				t.Errorf("buildQuery() qtype = %v, want %v", q.Qtype, tt.qType)
			}
			if q.Qclass != dns.ClassINET {
				t.Errorf("buildQuery() qclass = %v, want %v", q.Qclass, dns.ClassINET)
			}
		})
	}
}

// ============================================================================
// displayFlags Tests
// ============================================================================

func TestDisplayFlagsSetDisplay(t *testing.T) {
	tests := []struct {
		name     string
		initial  displayFlags
		flagName string
		val      bool
		check    func(d displayFlags) bool
	}{
		{
			name:     "set cmd true",
			initial:  displayFlags{},
			flagName: "cmd",
			val:      true,
			check:    func(d displayFlags) bool { return d.cmd },
		},
		{
			name:     "set comments false",
			initial:  displayFlags{comments: true},
			flagName: "comments",
			val:      false,
			check:    func(d displayFlags) bool { return !d.comments },
		},
		{
			name:     "set answer true",
			initial:  displayFlags{},
			flagName: "answer",
			val:      true,
			check:    func(d displayFlags) bool { return d.answer },
		},
		{
			name:     "unknown flag ignored",
			initial:  displayFlags{cmd: true},
			flagName: "unknown",
			val:      true,
			check:    func(d displayFlags) bool { return d.cmd && !d.answer },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.initial
			d.setDisplay(tt.flagName, tt.val)
			if !tt.check(d) {
				t.Errorf("setDisplay() check failed for %s", tt.flagName)
			}
		})
	}
}

// ============================================================================
// shortRData Tests
// ============================================================================

func TestShortRData(t *testing.T) {
	tests := []struct {
		name string
		rr   dns.RR
		want string
	}{
		{
			name: "A record",
			rr: &dns.A{
				Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("8.8.8.8"),
			},
			want: "8.8.8.8",
		},
		{
			name: "AAAA record",
			rr: &dns.AAAA{
				Hdr:  dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:4860:4860::8888"),
			},
			want: "2001:4860:4860::8888",
		},
		{
			name: "CNAME record",
			rr: &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.google.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "google.com.",
			},
			want: "google.com.",
		},
		{
			name: "NS record",
			rr: &dns.NS{
				Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.google.com.",
			},
			want: "ns1.google.com.",
		},
		{
			name: "MX record",
			rr: &dns.MX{
				Hdr:        dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10,
				Mx:         "smtp.google.com.",
			},
			want: "10 smtp.google.com.",
		},
		{
			name: "PTR record",
			rr: &dns.PTR{
				Hdr: dns.RR_Header{Name: "8.8.8.8.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
				Ptr: "dns.google.",
			},
			want: "dns.google.",
		},
		{
			name: "TXT record",
			rr: &dns.TXT{
				Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"v=spf1 include:_spf.google.com ~all"},
			},
			want: `"v=spf1 include:_spf.google.com ~all"`,
		},
		{
			name: "SOA record",
			rr: &dns.SOA{
				Hdr:     dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:      "ns1.google.com.",
				Mbox:    "admin.google.com.",
				Serial:  2024010101,
				Refresh: 900,
				Retry:   900,
				Expire:  1800,
				Minttl:  60,
			},
			want: "ns1.google.com. admin.google.com. 2024010101 900 900 1800 60",
		},
		{
			name: "SRV record",
			rr: &dns.SRV{
				Hdr:      dns.RR_Header{Name: "_ldap._tcp.google.com.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 300},
				Priority: 10,
				Weight:   20,
				Port:     389,
				Target:   "ldap.google.com.",
			},
			want: "10 20 389 ldap.google.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shortRData(tt.rr)
			if got != tt.want {
				t.Errorf("shortRData() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// formatFlags Tests
// ============================================================================

func TestFormatFlags(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Msg
		want string
	}{
		{
			name: "standard response",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:           true,
					Authoritative:      false,
					Truncated:          false,
					RecursionDesired:   true,
					RecursionAvailable: true,
				},
			},
			want: "qr rd ra",
		},
		{
			name: "authoritative response",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:           true,
					Authoritative:      true,
					Truncated:          false,
					RecursionDesired:   false,
					RecursionAvailable: true,
				},
			},
			want: "qr aa ra",
		},
		{
			name: "truncated response",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:           true,
					Authoritative:      false,
					Truncated:          true,
					RecursionDesired:   true,
					RecursionAvailable: false,
				},
			},
			want: "qr tc rd",
		},
		{
			name: "query without response",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:           false,
					Authoritative:      false,
					Truncated:          false,
					RecursionDesired:   true,
					RecursionAvailable: false,
				},
			},
			want: "rd",
		},
		{
			name: "no flags",
			msg:  &dns.Msg{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFlags(tt.msg)
			if got != tt.want {
				t.Errorf("formatFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// config.network() Tests
// ============================================================================

func TestConfigNetwork(t *testing.T) {
	tests := []struct {
		name    string
		useIPv4 bool
		useIPv6 bool
		base    string
		want    string
	}{
		{"default udp", false, false, "udp", "udp"},
		{"default tcp", false, false, "tcp", "tcp"},
		{"IPv4 udp", true, false, "udp", "udp4"},
		{"IPv4 tcp", true, false, "tcp", "tcp4"},
		{"IPv6 udp", false, true, "udp", "udp6"},
		{"IPv6 tcp", false, true, "tcp", "tcp6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{
				useIPv4: tt.useIPv4,
				useIPv6: tt.useIPv6,
			}
			got := cfg.network(tt.base)
			if got != tt.want {
				t.Errorf("config.network() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// config.serverDisplay() Tests
// ============================================================================

func TestConfigServerDisplay(t *testing.T) {
	tests := []struct {
		name   string
		proto  string
		server string
		port   string
		want   string
	}{
		{"udp server", "udp", "8.8.8.8", "53", "8.8.8.8#53"},
		{"tcp server", "tcp", "8.8.8.8", "53", "8.8.8.8#53"},
		{"https server", "https", "1.1.1.1", "443", "https://1.1.1.1"},
		{"http server", "http", "1.1.1.1", "80", "http://1.1.1.1"},
		{"tls server", "tls", "1.1.1.1", "853", "tls://1.1.1.1"},
		{"quic server", "quic", "dns.adguard.com", "853", "quic://dns.adguard.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{
				proto:  tt.proto,
				server: tt.server,
				port:   tt.port,
			}
			got := cfg.serverDisplay()
			if got != tt.want {
				t.Errorf("config.serverDisplay() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// applyQueryOption Tests
// ============================================================================

func TestApplyQueryOption(t *testing.T) {
	tests := []struct {
		name    string
		opt     string
		checkFn func(*config) bool
	}{
		{
			name:    "+short",
			opt:     "short",
			checkFn: func(c *config) bool { return c.display.short && c.display.answer },
		},
		{
			name:    "+tcp",
			opt:     "tcp",
			checkFn: func(c *config) bool { return c.useTCP },
		},
		{
			name:    "+notcp",
			opt:     "notcp",
			checkFn: func(c *config) bool { return !c.useTCP },
		},
		{
			name: "+all",
			opt:  "all",
			checkFn: func(c *config) bool {
				return c.display.cmd && c.display.comments && c.display.question &&
					c.display.answer && c.display.authority && c.display.additional && c.display.stats
			},
		},
		{
			name: "+noall",
			opt:  "noall",
			checkFn: func(c *config) bool {
				return !c.display.cmd && !c.display.comments && !c.display.question &&
					!c.display.answer && !c.display.authority && !c.display.additional && !c.display.stats
			},
		},
		{
			name:    "+noanswer",
			opt:     "noanswer",
			checkFn: func(c *config) bool { return !c.display.answer },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{
				display: displayFlags{
					cmd:        true,
					comments:   true,
					question:   true,
					answer:     true,
					authority:  true,
					additional: true,
					stats:      true,
				},
			}
			applyQueryOption(cfg, tt.opt)
			if !tt.checkFn(cfg) {
				t.Errorf("applyQueryOption(%s) check failed", tt.opt)
			}
		})
	}
}
