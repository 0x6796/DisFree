package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const providerURL = "https://riseup.net/provider.json"

type ProviderInfo struct {
	APIURI            string            `json:"api_uri"`
	APIVersion        string            `json:"api_version"`
	CACertFingerprint string            `json:"ca_cert_fingerprint"`
	CACertURI         string            `json:"ca_cert_uri"`
	Domain            string            `json:"domain"`
	Name              map[string]string `json:"name"`
	Services          []string          `json:"services"`
}

type ProviderTrust struct {
	Info        ProviderInfo
	CA          *x509.Certificate
	Fingerprint [sha256.Size]byte
	RawPEM      []byte
}

func fetchURL(ctx context.Context, url, accept string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "DisFree/0.4 pure-go")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s exceeded %d bytes", url, limit)
	}
	return b, nil
}

func normalizeSHA256Fingerprint(s string) (string, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		alg := strings.TrimSpace(s[:i])
		if !strings.EqualFold(alg, "SHA256") && !strings.EqualFold(alg, "SHA-256") {
			return "", fmt.Errorf("unsupported CA fingerprint algorithm %q", alg)
		}
		s = s[i+1:]
	}
	repl := strings.NewReplacer(":", "", " ", "", "\t", "", "\n", "", "\r", "")
	s = strings.ToLower(repl.Replace(s))
	if len(s) != sha256.Size*2 {
		return "", fmt.Errorf("invalid SHA-256 fingerprint length %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("invalid SHA-256 fingerprint: %w", err)
	}
	return s, nil
}

func loadProviderTrust(ctx context.Context) (*ProviderTrust, error) {
	rawProvider, err := fetchURL(ctx, providerURL, "application/json", 256<<10)
	if err != nil {
		return nil, fmt.Errorf("provider bootstrap: %w", err)
	}
	var info ProviderInfo
	if err := json.Unmarshal(rawProvider, &info); err != nil {
		return nil, fmt.Errorf("provider.json: %w", err)
	}
	if !strings.EqualFold(info.Domain, "riseup.net") {
		return nil, fmt.Errorf("unexpected provider domain %q", info.Domain)
	}
	if info.CACertURI == "" || info.CACertFingerprint == "" {
		return nil, errors.New("provider did not publish CA URI/fingerprint")
	}
	if !strings.HasPrefix(strings.ToLower(info.CACertURI), "https://") {
		return nil, errors.New("provider CA URI is not HTTPS")
	}

	wantHex, err := normalizeSHA256Fingerprint(info.CACertFingerprint)
	if err != nil {
		return nil, err
	}
	rawCA, err := fetchURL(ctx, info.CACertURI, "application/x-pem-file,text/plain", 256<<10)
	if err != nil {
		return nil, fmt.Errorf("fetch provider CA: %w", err)
	}
	block, _ := pem.Decode(rawCA)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("provider CA endpoint did not return a PEM certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse provider CA: %w", err)
	}
	if !ca.IsCA {
		return nil, errors.New("provider certificate is not a CA")
	}
	now := time.Now()
	if now.Before(ca.NotBefore) || now.After(ca.NotAfter) {
		return nil, fmt.Errorf("provider CA is outside validity window: %s -> %s", ca.NotBefore.Format(time.RFC3339), ca.NotAfter.Format(time.RFC3339))
	}

	got := sha256.Sum256(ca.Raw)
	gotHex := hex.EncodeToString(got[:])
	if !strings.EqualFold(gotHex, wantHex) {
		return nil, fmt.Errorf("provider CA fingerprint mismatch: provider.json=%s downloaded=%s", wantHex, gotHex)
	}
	return &ProviderTrust{Info: info, CA: ca, Fingerprint: got, RawPEM: append([]byte(nil), rawCA...)}, nil
}

func (p *ProviderTrust) tlsConfigForGateway(ep Endpoint, identity *Identity) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(p.CA)
	expectedCN := strings.SplitN(ep.Host, ".", 2)[0]

	return &tls.Config{
		Certificates: []tls.Certificate{identity.Pair},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		// OpenVPN gateway certificates are provider-CA identities rather than
		// normal WebPKI host certificates. We therefore do the full chain/EKU
		// and gateway-identity verification below instead of Go's DNS verifier.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("gateway returned no certificate")
			}
			leaf := cs.PeerCertificates[0]
			inter := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				if !bytes.Equal(cert.Raw, p.CA.Raw) {
					inter.AddCert(cert)
				}
			}
			chains, err := leaf.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inter,
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return fmt.Errorf("gateway certificate chain: %w", err)
			}
			if len(chains) == 0 {
				return errors.New("gateway certificate produced no trusted chain")
			}

			// Current Riseup gateway certs use the short gateway host as CN
			// (for example vpn23-mia for vpn23-mia.riseup.net). If a future
			// certificate has a usable SAN, allow normal hostname matching too.
			if leaf.Subject.CommonName != expectedCN {
				if err := leaf.VerifyHostname(ep.Host); err != nil {
					return fmt.Errorf("gateway identity mismatch: host=%s cn=%q", ep.Host, leaf.Subject.CommonName)
				}
			}
			return nil
		},
	}
}

func cmdProvider(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("provider takes no arguments")
	}
	trust, err := loadProviderTrust(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Provider:       %s (%s)\n", trust.Info.Name["en"], trust.Info.Domain)
	fmt.Printf("API version:    %s\n", trust.Info.APIVersion)
	fmt.Printf("CA URI:         %s\n", trust.Info.CACertURI)
	fmt.Printf("CA subject:     %s\n", trust.CA.Subject.String())
	fmt.Printf("CA validity:    %s -> %s\n", trust.CA.NotBefore.Format(time.RFC3339), trust.CA.NotAfter.Format(time.RFC3339))
	fmt.Printf("CA SHA-256:     %x\n", trust.Fingerprint)
	fmt.Println("Fingerprint matches provider.json.")
	return nil
}
