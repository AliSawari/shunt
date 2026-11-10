package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"shunt/internal/profile"
)

// CheckSettings configures the proxy checker tests.
type CheckSettings struct {
	TestConnect bool   `json:"testConnect"` // Test 1: connection to the proxy server
	TestThrough bool   `json:"testThrough"` // Test 2: connection through the proxy server
	TestLatency bool   `json:"testLatency"` // Test 3: proxy server latency
	TargetHost  string `json:"targetHost"`
	TargetPort  int    `json:"targetPort"`
	LoadPage    bool   `json:"loadPage"`
}

func DefaultCheckSettings() CheckSettings {
	return CheckSettings{TestConnect: true, TestThrough: true, TestLatency: true, TargetHost: "www.google.com", TargetPort: 80, LoadPage: true}
}

// CheckResult is the outcome of a proxy check.
type CheckResult struct {
	OK        bool     `json:"ok"`
	LatencyMs int64    `json:"latencyMs"`
	Lines     []string `json:"lines"`
	Verdict   string   `json:"verdict"`
}

// Check runs the proxy checker against px.
func Check(ctx context.Context, dial DialFunc, px *profile.Proxy, s CheckSettings) CheckResult {
	var res CheckResult
	logf := func(format string, a ...any) {
		res.Lines = append(res.Lines, fmt.Sprintf("[%s] ", time.Now().Format("15:04:05"))+fmt.Sprintf(format, a...))
	}
	if s.TargetHost == "" {
		s.TargetHost = "www.google.com"
	}
	if s.TargetPort <= 0 || s.TargetPort > 65535 {
		s.TargetPort = 80
	}
	fail := func(v string) CheckResult {
		res.Verdict = v
		logf("Testing finished: %s", v)
		return res
	}
	logf("Testing started.")
	logf("Proxy server: %s  protocol: %s  authentication: %s", px.HostPort(), px.Type, map[bool]string{true: "yes", false: "no"}[px.AuthEnabled])

	if s.TestConnect {
		logf("Test 1: connection to the proxy server")
		t0 := time.Now()
		c, err := timeoutDial(ctx, dial, px.HostPort(), 15*time.Second)
		if err != nil {
			logf("  Error: could not connect to %s: %v", px.HostPort(), err)
			return fail("Proxy is NOT reachable.")
		}
		c.Close()
		logf("  Connection established in %d ms.", time.Since(t0).Milliseconds())
		logf("  Test passed.")
	} else {
		logf("Test 1 skipped by settings.")
	}

	if s.TestThrough {
		logf("Test 2: connection through the proxy server to %s:%d", s.TargetHost, s.TargetPort)
		t0 := time.Now()
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		c, err := DialChain(cctx, dial, []*profile.Proxy{px}, s.TargetHost, uint16(s.TargetPort))
		cancel()
		if err != nil {
			logf("  Error: %v", err)
			return fail("Proxy is reachable but is NOT working with these settings.")
		}
		logf("  Connection to %s:%d established through the proxy in %d ms.", s.TargetHost, s.TargetPort, time.Since(t0).Milliseconds())
		if s.LoadPage {
			c.SetDeadline(time.Now().Add(20 * time.Second))
			t1 := time.Now()
			fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Shunt-ProxyChecker\r\nAccept: */*\r\nConnection: close\r\n\r\n", s.TargetHost)
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "HTTP/") {
				c.Close()
				if err != nil {
					logf("  Error: no HTTP response from the target host: %v", err)
				} else {
					logf("  Error: unexpected response from the target host: %q", strings.TrimSpace(line))
				}
				return fail("Proxy connects but the default web page could not be loaded.")
			}
			logf("  Web page reply received in %d ms: %s", time.Since(t1).Milliseconds(), strings.TrimSpace(line))
		}
		c.Close()
		logf("  Test passed.")
	} else {
		logf("Test 2 skipped by settings.")
	}

	if s.TestLatency {
		logf("Test 3: proxy server latency")
		var total time.Duration
		const rounds = 4
		n := 0
		for i := 0; i < rounds; i++ {
			t0 := time.Now()
			var c net.Conn
			var err error
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			if s.TestThrough {
				c, err = DialChain(cctx, dial, []*profile.Proxy{px}, s.TargetHost, uint16(s.TargetPort))
			} else {
				c, err = dial(cctx, "tcp", px.HostPort())
			}
			cancel()
			if err != nil {
				logf("  Round %d failed: %v", i+1, err)
				continue
			}
			c.Close()
			total += time.Since(t0)
			n++
		}
		if n == 0 {
			return fail("Latency test failed.")
		}
		res.LatencyMs = (total / time.Duration(n)).Milliseconds()
		logf("  Average latency = %d ms (%d of %d rounds).", res.LatencyMs, n, rounds)
		logf("  Test passed.")
	} else {
		logf("Test 3 skipped by settings.")
	}
	res.OK = true
	res.Verdict = "Proxy is ready to work with Shunt!"
	logf("Testing finished: %s", res.Verdict)
	return res
}

func timeoutDial(ctx context.Context, dial DialFunc, addr string, d time.Duration) (net.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return dial(cctx, "tcp", addr)
}
