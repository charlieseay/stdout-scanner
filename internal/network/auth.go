package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AuthResult holds authentication detection data for a service.
type AuthResult struct {
	IP       string      `json:"ip"`
	Hostname string      `json:"hostname,omitempty"`
	Services []AuthCheck `json:"services"`
}

// AuthCheck represents the auth status of a single service endpoint.
type AuthCheck struct {
	Port       uint16 `json:"port"`
	Service    string `json:"service,omitempty"`
	AuthType   string `json:"auth_type"`             // none, basic, bearer, form, sso, unknown
	StatusCode int    `json:"status_code,omitempty"`
	SSOProvider string `json:"sso_provider,omitempty"` // authentik, keycloak, okta, etc.
	LoginURL   string `json:"login_url,omitempty"`
	Open       bool   `json:"open"`                   // true = no auth required
}

// DetectAuth probes discovered devices for authentication requirements.
// Only checks HTTP/HTTPS ports. Never attempts credentials.
func DetectAuth(ctx context.Context, devices []Device) []AuthResult {
	var results []AuthResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	httpPorts := map[uint16]bool{
		80: true, 443: true, 8080: true, 8443: true,
		8888: true, 3000: true, 5000: true, 5001: true,
		5678: true, 8101: true, 8103: true, 8104: true,
		8106: true, 8107: true, 8108: true, 8109: true,
		8110: true, 8112: true, 8113: true, 9090: true,
		9443: true, 9925: true, 19999: true, 32400: true,
	}

	for _, dev := range devices {
		// Only check devices with HTTP ports
		var webPorts []Port
		for _, p := range dev.Ports {
			if httpPorts[p.Number] {
				webPorts = append(webPorts, p)
			}
		}
		if len(webPorts) == 0 {
			continue
		}

		wg.Add(1)
		go func(d Device, ports []Port) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := AuthResult{
				IP:       d.IP,
				Hostname: d.Hostname,
			}

			for _, p := range ports {
				check := checkAuth(ctx, d.IP, p)
				result.Services = append(result.Services, check)
			}

			if len(result.Services) > 0 {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(dev, webPorts)
	}
	wg.Wait()

	return results
}

func checkAuth(ctx context.Context, ip string, port Port) AuthCheck {
	check := AuthCheck{
		Port:    port.Number,
		Service: port.Service,
	}

	scheme := "http"
	if port.Number == 443 || port.Number == 8443 || port.Number == 9443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port.Number)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow one redirect to catch SSO redirects, then stop
			if len(via) >= 1 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		check.AuthType = "unknown"
		return check
	}
	req.Header.Set("User-Agent", "stdout-scanner/2.0")

	resp, err := client.Do(req)
	if err != nil {
		check.AuthType = "unknown"
		return check
	}
	defer resp.Body.Close()

	// Read a limited amount of body for form/SSO detection
	bodyBytes := make([]byte, 8192)
	n, _ := io.ReadAtLeast(resp.Body, bodyBytes, 1)
	body := string(bodyBytes[:n])
	io.Copy(io.Discard, resp.Body)

	check.StatusCode = resp.StatusCode

	// Classify based on response
	switch {
	case resp.StatusCode == 401:
		check.AuthType = classifyWWWAuth(resp.Header.Get("WWW-Authenticate"))
		check.Open = false

	case resp.StatusCode == 403:
		check.AuthType = "forbidden"
		check.Open = false

	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// Redirect — check if it's an SSO redirect
		location := resp.Header.Get("Location")
		if sso := detectSSO(location, body); sso != "" {
			check.AuthType = "sso"
			check.SSOProvider = sso
			check.LoginURL = location
			check.Open = false
		} else if strings.Contains(strings.ToLower(location), "login") ||
			strings.Contains(strings.ToLower(location), "signin") ||
			strings.Contains(strings.ToLower(location), "auth") {
			check.AuthType = "form"
			check.LoginURL = location
			check.Open = false
		} else {
			check.AuthType = "none"
			check.Open = true
		}

	case resp.StatusCode == 200:
		// Check if the page itself is a login form
		if isLoginPage(body) {
			check.AuthType = "form"
			check.Open = false
			if sso := detectSSOInBody(body); sso != "" {
				check.AuthType = "sso"
				check.SSOProvider = sso
			}
		} else {
			check.AuthType = "none"
			check.Open = true
		}

	default:
		check.AuthType = "unknown"
	}

	if check.AuthType != "none" && check.AuthType != "unknown" {
		fmt.Fprintf(os.Stderr, "    Auth %s:%d — %s", ip, port.Number, check.AuthType)
		if check.SSOProvider != "" {
			fmt.Fprintf(os.Stderr, " (%s)", check.SSOProvider)
		}
		fmt.Fprintln(os.Stderr)
	}

	return check
}

// classifyWWWAuth parses the WWW-Authenticate header.
func classifyWWWAuth(header string) string {
	if header == "" {
		return "basic"
	}
	h := strings.ToLower(header)
	switch {
	case strings.HasPrefix(h, "basic"):
		return "basic"
	case strings.HasPrefix(h, "bearer"):
		return "bearer"
	case strings.HasPrefix(h, "digest"):
		return "digest"
	case strings.HasPrefix(h, "negotiate"):
		return "negotiate"
	default:
		return "basic"
	}
}

// detectSSO checks if a redirect URL points to a known SSO provider.
func detectSSO(location, body string) string {
	loc := strings.ToLower(location)

	patterns := map[string][]string{
		"Authentik":  {"authentik", "/application/o/authorize", "goauthentik"},
		"Keycloak":   {"keycloak", "/auth/realms/", "/protocol/openid-connect"},
		"Okta":       {"okta.com", ".oktapreview.com"},
		"Auth0":      {"auth0.com", ".auth0.com"},
		"Azure AD":   {"login.microsoftonline.com", "login.microsoft.com"},
		"Google":     {"accounts.google.com/o/oauth2"},
		"GitHub":     {"github.com/login/oauth"},
		"Authelia":   {"authelia", "/api/verify"},
		"Cloudflare": {"cloudflareaccess.com", "access.cloudflare.com"},
		"Dex":        {"/dex/auth"},
		"Zitadel":    {"zitadel"},
	}

	for provider, keywords := range patterns {
		for _, keyword := range keywords {
			if strings.Contains(loc, keyword) {
				return provider
			}
		}
	}
	return ""
}

// detectSSOInBody checks HTML body for SSO login buttons/links.
func detectSSOInBody(body string) string {
	b := strings.ToLower(body)

	patterns := map[string][]string{
		"Authentik":  {"authentik", "goauthentik"},
		"Keycloak":   {"keycloak"},
		"Okta":       {"okta"},
		"Auth0":      {"auth0"},
		"Azure AD":   {"microsoftonline"},
		"Authelia":   {"authelia"},
		"Cloudflare": {"cloudflare access", "cloudflareaccess"},
	}

	for provider, keywords := range patterns {
		for _, keyword := range keywords {
			if strings.Contains(b, keyword) {
				return provider
			}
		}
	}
	return ""
}

// isLoginPage checks if HTML body contains login form indicators.
func isLoginPage(body string) bool {
	b := strings.ToLower(body)

	indicators := []string{
		"type=\"password\"",
		"type='password'",
		"name=\"password\"",
		"name=\"username\"",
		"name=\"email\"",
		"id=\"login",
		"class=\"login",
		"action=\"/login",
		"action=\"/signin",
		"action=\"/auth",
		"<title>login",
		"<title>sign in",
		"<title>log in",
		"please sign in",
		"please log in",
		"enter your password",
		"forgot password",
	}

	matches := 0
	for _, indicator := range indicators {
		if strings.Contains(b, indicator) {
			matches++
		}
	}

	// Need at least 2 indicators to be confident it's a login page
	return matches >= 2
}
