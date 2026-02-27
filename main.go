package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	quic "github.com/quic-go/quic-go"
)

const defaultTimeout = 5 * time.Second

// dohClient is reused across DoH requests to enable connection pooling.
var dohClient = &http.Client{Timeout: 10 * time.Second}

// displayFlags controls which sections of the dig-style output to show.
type displayFlags struct {
	cmd        bool // ";; <<>> vdig <<>> ..." banner
	comments   bool // ";; ANSWER SECTION:" etc.
	question   bool
	answer     bool
	authority  bool
	additional bool
	stats      bool // footer: query time, server, when, msg size
	short      bool // terse output: just rdata
}

// setDisplay sets the named display flag to val. Unknown names are ignored.
func (d *displayFlags) setDisplay(name string, val bool) {
	switch name {
	case "cmd":
		d.cmd = val
	case "comments":
		d.comments = val
	case "question":
		d.question = val
	case "answer":
		d.answer = val
	case "authority":
		d.authority = val
	case "additional":
		d.additional = val
	case "stats":
		d.stats = val
	}
}

// config holds all parsed CLI arguments.
type config struct {
	proto  string // "udp", "tcp", "tls", "quic", "https", "http"
	server string // host only (scheme stripped)
	port   string // default "53"
	domain string
	qType  uint16
	qClass uint16

	useTCP  bool // +tcp
	useIPv4 bool // -4
	useIPv6 bool // -6
	reverse bool // -x

	display displayFlags
}

// network returns the dial network string respecting -4/-6.
func (c *config) network(base string) string {
	if c.useIPv4 {
		return base + "4"
	}
	if c.useIPv6 {
		return base + "6"
	}
	return base
}

// serverDisplay returns the dig-style server string for the footer.
func (c *config) serverDisplay() string {
	switch c.proto {
	case "http", "https", "tls", "quic":
		return c.proto + "://" + c.server
	default:
		return c.server + "#" + c.port
	}
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fatalf("%v", err)
	}

	if cfg.server == "" {
		cfg.server = parseResolvConf()
	}

	reply, dur, err := exchange(cfg, buildQuery(cfg))
	if err != nil {
		fatalf("exchange: %v", err)
	}

	printResponse(cfg, reply, dur)
}

// parseArgs parses dig-compatible arguments:
//
//	vdig [@server] [name] [type] [class] [-p port] [-x addr] [-4] [-6] [+queryopt...]
func parseArgs(args []string) (*config, error) {
	cfg := &config{
		proto:  "udp",
		port:   "53",
		qType:  dns.TypeA,
		qClass: dns.ClassINET,
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

	var domain string
	portSet := false

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case strings.HasPrefix(arg, "@"):
			server := arg[1:]
			// Strip scheme and record the protocol.
			for _, s := range []string{"https://", "http://", "tls://", "quic://"} {
				if strings.HasPrefix(server, s) {
					cfg.proto = s[:len(s)-len("://")]
					server = server[len(s):]
					break
				}
			}
			// For non-DoH schemes, extract inline port from host:port.
			if cfg.proto != "http" && cfg.proto != "https" {
				if h, p, err := net.SplitHostPort(server); err == nil {
					server = h
					cfg.port = p
					portSet = true
				}
			}
			cfg.server = server

		case strings.HasPrefix(arg, "+"):
			applyQueryOption(cfg, arg[1:])

		case arg == "-p":
			i++
			if i >= len(args) {
				return nil, errors.New("-p requires a port number")
			}
			cfg.port = args[i]
			portSet = true

		case arg == "-x":
			i++
			if i >= len(args) {
				return nil, errors.New("-x requires an IP address")
			}
			ptr, err := reverseAddr(args[i])
			if err != nil {
				return nil, fmt.Errorf("bad address for -x: %w", err)
			}
			cfg.domain = ptr
			cfg.qType = dns.TypePTR
			cfg.reverse = true

		case arg == "-4":
			cfg.useIPv4 = true

		case arg == "-6":
			cfg.useIPv6 = true

		default:
			upper := strings.ToUpper(arg)
			if t, ok := dns.StringToType[upper]; ok {
				cfg.qType = t
			} else if c, ok := dns.StringToClass[upper]; ok {
				cfg.qClass = c
			} else {
				domain = arg
			}
		}
	}

	if !cfg.reverse {
		if domain != "" {
			cfg.domain = domain
		} else {
			cfg.domain = "."
			cfg.qType = dns.TypeNS
		}
	}

	cfg.domain = dns.Fqdn(cfg.domain)

	// +tcp overrides the default proto.
	if cfg.useTCP && cfg.proto == "udp" {
		cfg.proto = "tcp"
	}

	// Default port for DoT/DoQ is 853 (RFC 7858 / RFC 9250).
	if !portSet && (cfg.proto == "tls" || cfg.proto == "quic") {
		cfg.port = "853"
	}

	return cfg, nil
}

func applyQueryOption(cfg *config, opt string) {
	neg := strings.HasPrefix(opt, "no")
	if neg {
		opt = opt[2:]
	}
	val := !neg

	switch opt {
	case "short":
		cfg.display.short = val
		if val {
			// +short: only answer rdata, nothing else.
			cfg.display = displayFlags{answer: true, short: true}
		}
	case "tcp":
		cfg.useTCP = val
	case "all":
		// +all/+noall toggles every display flag (except short).
		short := cfg.display.short
		cfg.display = displayFlags{
			cmd: val, comments: val, question: val,
			answer: val, authority: val, additional: val,
			stats: val, short: short,
		}
	default:
		cfg.display.setDisplay(opt, val)
	}
}

// parseResolvConf reads the first nameserver from /etc/resolv.conf.
func parseResolvConf() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "127.0.0.1"
	}
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if after, ok := strings.CutPrefix(line, "nameserver"); ok {
			if s := strings.TrimSpace(after); s != "" {
				return s
			}
		}
	}
	return "127.0.0.1"
}

func buildQuery(cfg *config) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(cfg.domain, cfg.qType)
	msg.Question[0].Qclass = cfg.qClass
	return msg
}

// ------- Transport -------

// writeFrame writes a DNS message with a 2-byte length prefix (RFC 1035 §4.2.2).
func writeFrame(w io.Writer, msg []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// readFrame reads a 2-byte length prefix and the exact DNS message payload.
func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(r, resp); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return resp, nil
}

// streamExchange sends a DNS message over a framed stream (TCP/TLS)
// and reads the response.
func streamExchange(conn net.Conn, msg []byte) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(defaultTimeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	if err := writeFrame(conn, msg); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	return readFrame(conn)
}

func exchange(cfg *config, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("packing: %w", err)
	}

	start := time.Now()
	addr := net.JoinHostPort(cfg.server, cfg.port)

	var resp []byte
	switch cfg.proto {
	case "http", "https":
		resp, err = dohExchange(cfg.proto+"://"+cfg.server, wire)
	case "tls":
		resp, err = dotExchange(addr, cfg.server, wire)
	case "quic":
		resp, err = doqExchange(addr, cfg.server, wire)
	case "tcp":
		resp, err = tcpExchange(addr, cfg.network("tcp"), wire)
	default: // "udp"
		resp, err = udpExchange(addr, cfg.network("udp"), wire)
	}
	dur := time.Since(start)
	if err != nil {
		return nil, dur, err
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(resp); err != nil {
		return nil, dur, fmt.Errorf("unpacking: %w", err)
	}
	return reply, dur, nil
}

func udpExchange(addr, network string, msg []byte) ([]byte, error) {
	conn, err := net.DialTimeout(network, addr, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("udp dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(defaultTimeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("udp write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("udp read: %w", err)
	}
	return buf[:n], nil
}

func tcpExchange(addr, network string, msg []byte) ([]byte, error) {
	conn, err := net.DialTimeout(network, addr, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	defer conn.Close()
	return streamExchange(conn, msg)
}

func dohExchange(url string, msg []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("doh status %s: %s", resp.Status, string(body))
	}
	return io.ReadAll(resp.Body)
}

// dotExchange performs DNS over TLS (RFC 7858).
func dotExchange(addr, host string, msg []byte) ([]byte, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: defaultTimeout},
		"tcp", addr,
		&tls.Config{ServerName: host},
	)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()
	return streamExchange(conn, msg)
}

// doqExchange performs DNS over QUIC (RFC 9250).
func doqExchange(addr, host string, msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		ServerName: host,
		NextProtos: []string{"doq"},
		MinVersion: tls.VersionTLS13,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	if err := writeFrame(stream, msg); err != nil {
		return nil, fmt.Errorf("doq write: %w", err)
	}
	stream.Close()

	return readFrame(stream)
}

// ------- Reverse DNS -------

func reverseAddr(s string) (string, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP %q: %w", s, err)
	}
	if ip.Is4() {
		a := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", a[3], a[2], a[1], a[0]), nil
	}
	// IPv6: reverse nibble-by-nibble.
	a := ip.As16()
	var buf strings.Builder
	for i := len(a) - 1; i >= 0; i-- {
		fmt.Fprintf(&buf, "%x.%x.", a[i]&0x0f, a[i]>>4)
	}
	buf.WriteString("ip6.arpa.")
	return buf.String(), nil
}

// ------- Output -------

func printResponse(cfg *config, msg *dns.Msg, dur time.Duration) {
	// Banner.
	if cfg.display.cmd {
		if cfg.reverse {
			fmt.Printf("\n; <<>> vdig <<>> -x %s\n", cfg.domain)
		} else {
			fmt.Printf("\n; <<>> vdig <<>> %s %s\n", cfg.domain, dns.TypeToString[cfg.qType])
		}
		fmt.Println(";; global options: +cmd")
	}

	// Header.
	if cfg.display.comments {
		printHeader(msg)
	}

	// Question section.
	if cfg.display.question {
		fmt.Println("\n;; QUESTION SECTION:")
		for _, q := range msg.Question {
			fmt.Printf(";%-23s\t\t%s\t%s\n",
				q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
		}
	}

	// Resource sections — table-driven to avoid repeating the same pattern.
	type section struct {
		name  string
		show  bool
		short bool
		rrs   []dns.RR
	}
	for _, s := range []section{
		{"ANSWER", cfg.display.answer || cfg.display.short, cfg.display.short, msg.Answer},
		{"AUTHORITY", cfg.display.authority && !cfg.display.short, false, msg.Ns},
		{"ADDITIONAL", cfg.display.additional && !cfg.display.short, false, msg.Extra},
	} {
		if !s.show {
			continue
		}
		if cfg.display.comments && !s.short {
			fmt.Printf("\n;; %s SECTION:\n", s.name)
		}
		for _, rr := range s.rrs {
			// Skip OPT pseudo-records.
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			if s.short {
				fmt.Println(shortRData(rr))
			} else {
				fmt.Println(rr.String())
			}
		}
	}

	// Footer.
	if cfg.display.stats {
		fmt.Printf("\n;; Query time: %d msec\n", dur.Milliseconds())
		fmt.Printf(";; SERVER: %s\n", cfg.serverDisplay())
		fmt.Printf(";; WHEN: %s\n", time.Now().Format(time.RFC1123))
		fmt.Printf(";; MSG SIZE  rcvd: %d\n\n", msg.Len())
	}
}

func printHeader(msg *dns.Msg) {
	fmt.Println(";; Got answer:")

	op := "QUERY"
	if msg.Opcode != 0 {
		if s, ok := dns.OpcodeToString[msg.Opcode]; ok {
			op = s
		} else {
			op = fmt.Sprintf("OpCode%d", msg.Opcode)
		}
	}

	rcode := dns.RcodeToString[msg.Rcode]
	if rcode == "" {
		rcode = fmt.Sprintf("RCODE%d", msg.Rcode)
	}

	fmt.Printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n", op, rcode, msg.Id)
	fmt.Printf(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		formatFlags(msg), len(msg.Question), len(msg.Answer), len(msg.Ns), len(msg.Extra))
}

// shortRData returns just the rdata portion of an RR for +short output.
func shortRData(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return v.Target
	case *dns.NS:
		return v.Ns
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *dns.PTR:
		return v.Ptr
	case *dns.TXT:
		var parts []string
		for _, s := range v.Txt {
			parts = append(parts, fmt.Sprintf("%q", s))
		}
		return strings.Join(parts, " ")
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	default:
		// Fallback: strip the header (name, TTL, class, type) from String().
		s := rr.String()
		fields := strings.SplitN(s, "\t", 5)
		if len(fields) >= 5 {
			return fields[4]
		}
		return s
	}
}

func formatFlags(msg *dns.Msg) string {
	var flags []string
	if msg.Response {
		flags = append(flags, "qr")
	}
	if msg.Authoritative {
		flags = append(flags, "aa")
	}
	if msg.Truncated {
		flags = append(flags, "tc")
	}
	if msg.RecursionDesired {
		flags = append(flags, "rd")
	}
	if msg.RecursionAvailable {
		flags = append(flags, "ra")
	}
	return strings.Join(flags, " ")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
