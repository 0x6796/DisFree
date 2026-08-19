package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version = "0.22.0-crossplatform-handoff"
	baseURL = "https://api.black.riseup.net"
)

type Service struct {
	Gateways             []Gateway      `json:"gateways"`
	Locations            map[string]any `json:"locations"`
	OpenVPNConfiguration map[string]any `json:"openvpn_configuration"`
	Serial               any            `json:"serial"`
	Version              any            `json:"version"`
}

type Gateway struct {
	Host         string `json:"host"`
	IPAddress    string `json:"ip_address"`
	Location     string `json:"location"`
	Capabilities struct {
		Transport []Transport `json:"transport"`
	} `json:"capabilities"`
}

type Transport struct {
	Type      string         `json:"type"`
	Ports     []string       `json:"ports"`
	Protocols []string       `json:"protocols"`
	Options   map[string]any `json:"options,omitempty"`
}

type Endpoint struct {
	Host, IP, Location, Protocol string
	Port                         int
}

func (e Endpoint) Address() string { return net.JoinHostPort(e.IP, strconv.Itoa(e.Port)) }

type API struct{ http *http.Client }

func newAPI() *API {
	return &API{http: &http.Client{Timeout: 25 * time.Second}}
}

func (a *API) get(ctx context.Context, path, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "DisFree/0.1 pure-go")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Riseup API returned %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (a *API) service(ctx context.Context) (*Service, error) {
	b, err := a.get(ctx, "/3/config/eip-service.json", "application/json")
	if err != nil {
		return nil, err
	}
	var s Service
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if len(s.Gateways) == 0 {
		return nil, errors.New("Riseup returned zero gateways")
	}
	return &s, nil
}

type Identity struct {
	Raw  []byte
	Leaf *x509.Certificate
	Pair tls.Certificate
}

func parseIdentity(raw []byte) (*Identity, error) {
	rest := raw
	var certPEM, keyPEM bytes.Buffer
	var leaf *x509.Certificate
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		switch block.Type {
		case "CERTIFICATE":
			_ = pem.Encode(&certPEM, block)
			if leaf == nil {
				c, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, err
				}
				leaf = c
			}
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
			_ = pem.Encode(&keyPEM, block)
		}
	}
	if leaf == nil {
		return nil, errors.New("identity has no certificate")
	}
	if keyPEM.Len() == 0 {
		return nil, errors.New("identity has no private key")
	}
	pair, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("certificate/key validation failed: %w", err)
	}
	pair.Leaf = leaf
	return &Identity{Raw: append([]byte(nil), raw...), Leaf: leaf, Pair: pair}, nil
}

func (a *API) identity(ctx context.Context) (*Identity, error) {
	b, err := a.get(ctx, "/3/cert", "text/html")
	if err != nil {
		return nil, err
	}
	return parseIdentity(b)
}

func saveIdentity(id *Identity, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*.pem")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(id.Raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func endpoints(s *Service, transportType string) []Endpoint {
	var out []Endpoint
	for _, g := range s.Gateways {
		for _, t := range g.Capabilities.Transport {
			if !strings.EqualFold(t.Type, transportType) {
				continue
			}
			for _, proto := range t.Protocols {
				for _, p := range t.Ports {
					port, err := strconv.Atoi(p)
					if err != nil || port < 1 || port > 65535 {
						continue
					}
					out = append(out, Endpoint{Host: g.Host, IP: g.IPAddress, Location: g.Location, Protocol: strings.ToLower(proto), Port: port})
				}
			}
		}
	}
	return out
}

type Probe struct {
	Endpoint Endpoint
	Latency  time.Duration
	Err      error
}

func probeTCP(ctx context.Context, s *Service, timeout time.Duration) []Probe {
	var eps []Endpoint
	for _, ep := range endpoints(s, "openvpn") {
		if ep.Protocol == "tcp" {
			eps = append(eps, ep)
		}
	}
	results := make([]Probe, len(eps))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func(i int, ep Endpoint) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Probe{ep, 0, ctx.Err()}
				return
			}
			start := time.Now()
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", ep.Address())
			elapsed := time.Since(start)
			if c != nil {
				_ = c.Close()
			}
			results[i] = Probe{Endpoint: ep, Latency: elapsed, Err: err}
		}(i, ep)
	}
	wg.Wait()
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Err == nil && results[j].Err != nil {
			return true
		}
		if results[i].Err != nil && results[j].Err == nil {
			return false
		}
		return results[i].Latency < results[j].Latency
	})
	return results
}

func defaultIdentityPath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		h, _ := os.UserHomeDir()
		d = filepath.Join(h, ".config")
	}
	return filepath.Join(d, "disfree", "identity.pem")
}

func main() {
	platformSetWindowBranding()
	if len(os.Args) < 2 {
		if cmd := platformDefaultCommand(); cmd != "" {
			os.Args = append(os.Args, cmd)
		} else {
			usage()
			os.Exit(2)
		}
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println("DisFree", version)
	case "winselftest":
		err = cmdWindowsSelfTest()
	case "gateways":
		err = cmdGateways(ctx, os.Args[2:])
	case "probe":
		err = cmdProbe(ctx, os.Args[2:])
	case "wire":
		err = cmdWire(ctx, os.Args[2:])
	case "tlsprobe":
		err = cmdTLSProbe(ctx, os.Args[2:])
	case "provider":
		err = cmdProvider(ctx, os.Args[2:])
	case "keyprobe":
		err = cmdKeyProbe(ctx, os.Args[2:])
	case "pushprobe":
		err = cmdPushProbe(ctx, os.Args[2:])
	case "dataprobe":
		err = cmdDataProbe(ctx, os.Args[2:])
	case "tunprobe":
		err = cmdTunProbe()
	case "vpntunprobe":
		err = cmdVPNTunProbe(ctx, os.Args[2:])
	case "run":
		err = cmdRunVPN(ctx, os.Args[2:])
	case "discord":
		err = cmdDiscordVPN(ctx, os.Args[2:])
	case "__tunprobe_child":
		err = tunProbeChild()
	case "__vpntun_child":
		err = vpnTunChild(os.Args[2:])
	case "__vpnapp_child":
		err = vpnAppChild(os.Args[2:])
	case "__vpnproxy_child":
		err = vpnProxyChild(os.Args[2:])
	case "identity":
		err = cmdIdentity(ctx, os.Args[2:])
	case "bootstrap":
		err = cmdBootstrap(ctx, os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`DisFree %s

Pure-Go Riseup VPN client experiment.

Commands:
  gateways   Fetch current Riseup gateways and crypto parameters
  probe      Measure TCP reachability/latency to VPN endpoints
  wire       Perform real UDP OpenVPN reset handshake in pure Go
  provider   Verify Riseup provider metadata and VPN CA fingerprint
  tlsprobe   Establish and authenticate TLS inside the control channel
  keyprobe   Complete Key Method 2 and derive data-channel keys
  pushprobe  Request/parse VPN session configuration without applying it
  dataprobe  Send a real encrypted DNS packet over P_DATA_V2 without TUN
  tunprobe   Prove rootless isolated TUN capture in a private network namespace
  vpntunprobe End-to-end ordinary socket -> TUN -> Riseup -> TUN, rootless
  run        Run any application only through the DisFree VPN namespace
  discord    Restart Discord inside the DisFree VPN namespace
  identity   Fetch and securely save the anonymous client cert/key
  bootstrap  Run API + probe + identity bootstrap, without changing routes
  winselftest Validate embedded Windows packet-filter runtime
  version    Print version

No command invokes an OpenVPN binary. Probe commands do not create TUN or alter host routes.
`, version)
}

func cmdGateways(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gateways", flag.ContinueOnError)
	limit := fs.Int("limit", 0, "max gateways (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := newAPI().service(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Riseup service: gateways=%d version=%v serial=%v\n", len(s.Gateways), s.Version, s.Serial)
	keys := make([]string, 0, len(s.OpenVPNConfiguration))
	for k := range s.OpenVPNConfiguration {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("Advertised VPN parameters:")
	for _, k := range keys {
		fmt.Printf("  %-20s %v\n", k+":", s.OpenVPNConfiguration[k])
	}
	n := len(s.Gateways)
	if *limit > 0 && *limit < n {
		n = *limit
	}
	fmt.Println("\nGateways:")
	for _, g := range s.Gateways[:n] {
		var ts []string
		for _, t := range g.Capabilities.Transport {
			ts = append(ts, fmt.Sprintf("%s[%s:%s]", t.Type, strings.Join(t.Protocols, ","), strings.Join(t.Ports, ",")))
		}
		fmt.Printf("  %-24s %-16s %-12s %s\n", g.Host, g.IPAddress, g.Location, strings.Join(ts, " "))
	}
	return nil
}

func cmdProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	top := fs.Int("top", 10, "best endpoints to show")
	timeout := fs.Duration("timeout", 1500*time.Millisecond, "TCP timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := newAPI().service(ctx)
	if err != nil {
		return err
	}
	rs := probeTCP(ctx, s, *timeout)
	shown, reachable := 0, 0
	for _, r := range rs {
		if r.Err == nil {
			reachable++
			if shown < *top {
				shown++
				fmt.Printf("%2d. %-12s %-24s %-21s %7s TCP/%d\n", shown, r.Endpoint.Location, r.Endpoint.Host, r.Endpoint.IP, r.Latency.Round(time.Millisecond), r.Endpoint.Port)
			}
		}
	}
	if reachable == 0 {
		return errors.New("no advertised TCP endpoint reachable")
	}
	fmt.Printf("\n%d/%d TCP endpoints reachable.\n", reachable, len(rs))
	return nil
}

func cmdIdentity(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	out := fs.String("out", defaultIdentityPath(), "identity PEM path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fetchIdentity(ctx, *out)
}

func fetchIdentity(ctx context.Context, out string) error {
	id, err := newAPI().identity(ctx)
	if err != nil {
		return err
	}
	if err := saveIdentity(id, out); err != nil {
		return err
	}
	fmt.Printf("Identity stored: %s\n", out)
	fmt.Printf("  subject: %s\n", id.Leaf.Subject.String())
	fmt.Printf("  valid:   %s -> %s\n", id.Leaf.NotBefore.Format(time.RFC3339), id.Leaf.NotAfter.Format(time.RFC3339))
	fmt.Printf("  expires: %s\n", time.Until(id.Leaf.NotAfter).Round(time.Hour))
	return nil
}

func cmdBootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	out := fs.String("identity", defaultIdentityPath(), "identity PEM path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a := newAPI()
	s, err := a.service(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("[1/3] API OK: %d gateways\n", len(s.Gateways))
	rs := probeTCP(ctx, s, 1500*time.Millisecond)
	shown := 0
	fmt.Println("[2/3] Best reachable endpoints:")
	for _, r := range rs {
		if r.Err == nil && shown < 5 {
			shown++
			fmt.Printf("      %-12s %-24s %s TCP/%d\n", r.Endpoint.Location, r.Endpoint.Host, r.Latency.Round(time.Millisecond), r.Endpoint.Port)
		}
	}
	if shown == 0 {
		return errors.New("API works but no TCP gateway was reachable")
	}
	fmt.Println("[3/3] Anonymous client identity:")
	if err := fetchIdentity(ctx, *out); err != nil {
		return err
	}
	fmt.Println("Bootstrap complete. No route/interface was changed.")
	return nil
}
