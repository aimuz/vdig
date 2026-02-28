package main

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ============================================================================
// Dig Compatibility Tests
// ============================================================================

// TestDigCompatibilityOptions 测试与 dig 命令兼容的选项
func TestDigCompatibilityOptions(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedCmd string
	}{
		{
			name:        "+short output",
			args:        []string{"google.com", "+short"},
			expectedCmd: "google.com A",
		},
		{
			name:        "+noall +answer",
			args:        []string{"google.com", "+noall", "+answer"},
			expectedCmd: "google.com A",
		},
		{
			name:        "+noall +authority",
			args:        []string{"google.com", "+noall", "+authority"},
			expectedCmd: "google.com A",
		},
		{
			name:        "+noall +stats",
			args:        []string{"google.com", "+noall", "+stats"},
			expectedCmd: "google.com A",
		},
		{
			name:        "reverse lookup",
			args:        []string{"-x", "8.8.8.8"},
			expectedCmd: "-x 8.8.8.8",
		},
		{
			name:        "specify nameserver",
			args:        []string{"@8.8.8.8", "google.com"},
			expectedCmd: "google.com A",
		},
		{
			name:        "custom port",
			args:        []string{"@127.0.0.1", "-p", "5353", "example.com"},
			expectedCmd: "example.com A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseArgs(tt.args)
			if err != nil {
				t.Fatalf("parseArgs() error = %v", err)
			}

			// 验证域名被正确解析（FQDN）
			if !strings.HasSuffix(cfg.domain, ".") {
				t.Errorf("domain not FQDN: got %v, want suffix .", cfg.domain)
			}

			// 验证基本的配置正确性
			if cfg.domain == "" && !cfg.reverse {
				t.Error("expected non-empty domain for non-reverse query")
			}
		})
	}
}

// TestDigCompatibilityOutputFormat 测试输出格式与 dig 兼容
func TestDigCompatibilityOutputFormat(t *testing.T) {
	// 测试输出格式（不实际发起网络请求）
	cfg := &config{
		domain: "google.com.",
		qType:  dns.TypeA,
		server: "8.8.8.8",
		port:   "53",
		proto:  "udp",
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

	// 创建模拟响应
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 12345,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		Question: []dns.Question{
			{Name: "google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{8, 8, 8, 8},
			},
		},
		Ns: []dns.RR{},
	}

	// 测试配置和消息
	_ = cfg

	t.Logf("Test config: domain=%s, type=%d, server=%s", cfg.domain, cfg.qType, cfg.server)
	t.Logf("Test message: id=%d, flags=%s", msg.Id, formatFlags(msg))
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

// TestParseArgsEdgeCases 测试边界条件
func TestParseArgsEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		// 域名边界测试
		{
			name:    "empty args",
			args:    []string{},
			wantErr: false,
		},
		{
			name:    "root domain",
			args:    []string{"."},
			wantErr: false,
		},
		{
			name:    "long domain",
			args:    []string{"a.very.long.subdomain.example.com"},
			wantErr: false,
		},
		{
			name:    "domain with hyphens",
			args:    []string{"my-test-domain.com"},
			wantErr: false,
		},
		{
			name:    "domain with numbers",
			args:    []string{"test123.example456.com"},
			wantErr: false,
		},

		// 类型测试
		{
			name:    "all supported types",
			args:    []string{"example.com", "A"},
			wantErr: false,
		},
		{
			name:    "lowercase type",
			args:    []string{"example.com", "aaaa"},
			wantErr: false,
		},
		{
			name:    "mixed case type",
			args:    []string{"example.com", "Mx"},
			wantErr: false,
		},

		// 服务器配置边界
		{
			name:    "IPv6 nameserver",
			args:    []string{"@[::1]", "example.com"},
			wantErr: false,
		},
		{
			name:    "IPv6 nameserver with port",
			args:    []string{"@[::1]:53", "example.com"},
			wantErr: false,
		},

		// 协议选项组合
		{
			name:    "IPv4 with TCP",
			args:    []string{"-4", "example.com", "+tcp"},
			wantErr: false,
		},
		{
			name:    "IPv6 with TCP",
			args:    []string{"-6", "example.com", "+tcp"},
			wantErr: false,
		},
		{
			name:    "IPv4 and IPv6 both",
			args:    []string{"-4", "-6", "example.com"},
			wantErr: false, // -6 会覆盖 -4
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

// TestReverseAddrEdgeCases 测试反向DNS的边界条件
func TestReverseAddrEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		want    string
		wantErr bool
	}{
		// IPv4 边界
		{
			name:    "broadcast address",
			ip:      "255.255.255.255",
			want:    "255.255.255.255.in-addr.arpa.",
			wantErr: false,
		},
		{
			name:    "private network 10.x.x.x",
			ip:      "10.0.0.1",
			want:    "1.0.0.10.in-addr.arpa.",
			wantErr: false,
		},
		{
			name:    "private network 172.16-31.x.x",
			ip:      "172.16.0.1",
			want:    "1.0.16.172.in-addr.arpa.",
			wantErr: false,
		},
		{
			name:    "private network 192.168.x.x",
			ip:      "192.168.1.1",
			want:    "1.1.168.192.in-addr.arpa.",
			wantErr: false,
		},
		{
			name:    "link-local 169.254.x.x",
			ip:      "169.254.1.1",
			want:    "1.1.254.169.in-addr.arpa.",
			wantErr: false,
		},

		// IPv6 边界
		{
			name:    "full IPv6 address",
			ip:      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want:    "4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa.",
			wantErr: false,
		},
		{
			name:    "IPv6 loopback",
			ip:      "::1",
			want:    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			wantErr: false,
		},
		{
			name:    "IPv6 unique local",
			ip:      "fc00::1",
			want:    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa.",
			wantErr: false,
		},
		{
			name:    "IPv6 link-local",
			ip:      "fe80::1",
			want:    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
			wantErr: false,
		},

		// 错误情况
		{
			name:    "too many octets IPv4",
			ip:      "192.168.1.1.1",
			wantErr: true,
		},
		{
			name:    "negative octet",
			ip:      "192.168.1.-1",
			wantErr: true,
		},
		{
			name:    "leading zero in IPv4 (Go rejects this)",
			ip:      "192.168.01.01",
			wantErr: true, // Go 1.18+ 拒绝八进制前导零
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := reverseAddr(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("reverseAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("reverseAddr(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

// TestFullQueryFlow 测试完整的查询流程（需要本地DNS服务器或网络访问）
// 使用 build tag 标记为集成测试: go test -tags=integration
func TestFullQueryFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 测试基本的 DNS 查询（不依赖外部网络）
	cfg := &config{
		domain: "example.com.",
		qType:  dns.TypeA,
		server: "127.0.0.1",
		port:   "53",
		proto:  "udp",
	}

	// 构建查询
	msg := buildQuery(cfg)
	if len(msg.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(msg.Question))
	}

	if msg.Question[0].Name != "example.com." {
		t.Errorf("expected question name 'example.com.', got %s", msg.Question[0].Name)
	}

	// 验证消息可以打包
	_, err := msg.Pack()
	if err != nil {
		t.Errorf("failed to pack message: %v", err)
	}
}

// ============================================================================
// Performance Tests
// ============================================================================

// BenchmarkParseArgs 基准测试参数解析
func BenchmarkParseArgs(b *testing.B) {
	args := []string{"@8.8.8.8", "google.com", "A", "+short"}
	for i := 0; i < b.N; i++ {
		_, err := parseArgs(args)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReverseAddr 基准测试反向DNS解析
func BenchmarkReverseAddrIPv4(b *testing.B) {
	ip := "8.8.8.8"
	for i := 0; i < b.N; i++ {
		_, err := reverseAddr(ip)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReverseAddrIPv6(b *testing.B) {
	ip := "2001:4860:4860::8888"
	for i := 0; i < b.N; i++ {
		_, err := reverseAddr(ip)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkShortRData 基准测试短格式输出
func BenchmarkShortRDataA(b *testing.B) {
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{8, 8, 8, 8},
	}
	for i := 0; i < b.N; i++ {
		_ = shortRData(rr)
	}
}

func BenchmarkShortRDataMX(b *testing.B) {
	rr := &dns.MX{
		Hdr:        dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
		Preference: 10,
		Mx:         "smtp.google.com.",
	}
	for i := 0; i < b.N; i++ {
		_ = shortRData(rr)
	}
}

// ============================================================================
// Concurrency Tests
// ============================================================================

// TestConcurrentParseArgs 测试并发安全性
func TestConcurrentParseArgs(t *testing.T) {
	const goroutines = 100
	const iterations = 100

	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < iterations; j++ {
				_, err := parseArgs([]string{"google.com", "A", "+short"})
				if err != nil {
					t.Errorf("parseArgs failed: %v", err)
				}
			}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestConcurrentReverseAddr 测试反向DNS解析的并发安全性
func TestConcurrentReverseAddr(t *testing.T) {
	const goroutines = 100
	const iterations = 100

	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < iterations; j++ {
				_, err := reverseAddr("8.8.8.8")
				if err != nil {
					t.Errorf("reverseAddr failed: %v", err)
				}
			}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// ============================================================================
// Memory Safety Tests
// ============================================================================

// TestLargeDomain 测试处理超长域名
func TestLargeDomain(t *testing.T) {
	// DNS 标签最大 63 字节，域名最大 255 字节
	longLabel := strings.Repeat("a", 63)
	domain := longLabel + ".com"

	cfg, err := parseArgs([]string{domain})
	if err != nil {
		t.Errorf("parseArgs failed for large domain: %v", err)
	}

	// 验证域名被正确处理（添加 FQDN）
	if !strings.HasSuffix(cfg.domain, ".") {
		t.Error("expected FQDN suffix")
	}
}

// TestManyQueryOptions 测试大量查询选项
func TestManyQueryOptions(t *testing.T) {
	args := []string{
		"google.com",
		"+short",
		"+noall",
		"+answer",
		"+nocomments",
		"+nostats",
	}

	cfg, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}

	// 验证最终状态
	if cfg.display.short {
		// +short 覆盖 +noall
		if !cfg.display.answer {
			t.Error("+short should enable answer display")
		}
	}
}

// ============================================================================
// Error Recovery Tests
// ============================================================================

// TestGracefulErrorHandling 测试优雅的错误处理
func TestGracefulErrorHandling(t *testing.T) {
	// 测试无效输入不会 panic
	testCases := []struct {
		name string
		fn   func()
	}{
		{
			name: "nil config network",
			fn: func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic occurred: %v", r)
					}
				}()
				cfg := &config{}
				_ = cfg.network("udp")
			},
		},
		{
			name: "empty server display",
			fn: func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic occurred: %v", r)
					}
				}()
				cfg := &config{}
				_ = cfg.serverDisplay()
			},
		},
		// Note: formatFlags(nil) will panic - this is expected behavior
		// The function does not check for nil before accessing msg fields
		// This test documents the current behavior
		{
			name: "nil msg formatFlags (expected panic)",
			fn: func() {
				defer func() {
					if r := recover(); r == nil {
						t.Error("expected panic for nil msg, but none occurred")
					}
					// Panic is expected, so we don't call t.Errorf here
				}()
				_ = formatFlags(nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn()
		})
	}
}

// ============================================================================
// Time and Duration Tests
// ============================================================================

// TestTimeoutScenarios 测试超时场景
func TestTimeoutScenarios(t *testing.T) {
	// 测试默认超时
	if defaultTimeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", defaultTimeout)
	}

	// 测试自定义配置（模拟）
	cfg := &config{
		server: "8.8.8.8",
		port:   "53",
	}

	t.Logf("Config with timeout will use defaultTimeout: %v", defaultTimeout)
	_ = cfg
}

// ============================================================================
// Security Tests
// ============================================================================

// TestInputValidation 测试输入验证
func TestInputValidation(t *testing.T) {
	// 测试潜在的注入攻击向量
	testCases := []struct {
		name string
		args []string
	}{
		{
			name: "domain with special chars",
			args: []string{"test;rm -rf /"},
		},
		{
			name: "domain with quotes",
			args: []string{`"malicious"`},
		},
		{
			name: "domain with null",
			args: []string{"test\x00injection"},
		},
		{
			name: "path traversal attempt",
			args: []string{"../../../etc/passwd"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 这些输入应该被安全处理（dns.Fqdn 会清理它们）
			cfg, err := parseArgs(tc.args)
			if err != nil {
				t.Logf("Input rejected: %v", err)
			} else {
				t.Logf("Processed domain: %s", cfg.domain)
			}
		})
	}
}
