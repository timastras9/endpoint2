package tools

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ToolFunc func(params map[string]string, state interface{}) (string, bool, error)

type Tool struct {
	Name        string
	Description string
	RunInSandbox bool
	Execute     ToolFunc
}

var (
	registry   = make(map[string]*Tool)
	registryMu sync.RWMutex
)

func Register(t *Tool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[t.Name] = t
}

func Get(name string) (*Tool, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	if t, ok := registry[name]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("tool not found: %s", name)
}

func GetPrompt() string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	prompt := "<tools>\n"
	for _, t := range registry {
		prompt += fmt.Sprintf(`<tool name="%s">%s</tool>`+"\n", t.Name, t.Description)
	}
	prompt += "</tools>"
	return prompt
}

func init() {
	Register(&Tool{
		Name:         "terminal_execute",
		Description:  "Execute a shell command. Parameters: command (required)",
		RunInSandbox: false,
		Execute:      executeTerminal,
	})
	Register(&Tool{
		Name:         "port_scan",
		Description:  "Scan ports on a target. Parameters: target (required - IP or hostname), ports (optional - comma-separated or range like 1-1000, defaults to common ports)",
		RunInSandbox: false,
		Execute:      executePortScan,
	})
	Register(&Tool{
		Name:         "report_vulnerability",
		Description:  "Report a discovered vulnerability. Parameters: title (required), severity (required: critical/high/medium/low/info), description (required), url (required - where it was found)",
		RunInSandbox: false,
		Execute:      executeReportVulnerability,
	})
	Register(&Tool{
		Name:         "finish_scan",
		Description:  "Complete scan with report. Parameters: summary (required)",
		RunInSandbox: false,
		Execute: func(params map[string]string, _ interface{}) (string, bool, error) {
			return params["summary"], true, nil
		},
	})
	Register(&Tool{
		Name:         "thinking",
		Description:  "Plan next steps. Parameters: thought (required)",
		RunInSandbox: false,
		Execute: func(params map[string]string, _ interface{}) (string, bool, error) {
			return "Recorded: " + params["thought"], false, nil
		},
	})
	Register(&Tool{
		Name:         "ssl_scan",
		Description:  "Scan SSL/TLS configuration of a target. Parameters: target (required - hostname), port (optional - defaults to 443)",
		RunInSandbox: false,
		Execute:      executeSSLScan,
	})
	Register(&Tool{
		Name:         "dir_scan",
		Description:  "Scan for common directories and sensitive files. Parameters: target (required - base URL like https://example.com)",
		RunInSandbox: false,
		Execute:      executeDirScan,
	})
	Register(&Tool{
		Name:         "cors_scan",
		Description:  "Test CORS configuration for misconfigurations. Parameters: target (required - URL to test)",
		RunInSandbox: false,
		Execute:      executeCORSScan,
	})
	Register(&Tool{
		Name:         "cookie_scan",
		Description:  "Analyze cookies for security issues. Parameters: target (required - URL to test)",
		RunInSandbox: false,
		Execute:      executeCookieScan,
	})
	Register(&Tool{
		Name:         "http_methods_scan",
		Description:  "Test for dangerous HTTP methods enabled. Parameters: target (required - URL to test)",
		RunInSandbox: false,
		Execute:      executeHTTPMethodsScan,
	})
	Register(&Tool{
		Name:         "sqli_scan",
		Description:  "Test for SQL injection vulnerabilities. Parameters: target (required - URL with parameters to test, e.g., https://example.com/page?id=1)",
		RunInSandbox: false,
		Execute:      executeSQLiScan,
	})
	Register(&Tool{
		Name:         "xss_scan",
		Description:  "Test for Cross-Site Scripting (XSS) vulnerabilities. Parameters: target (required - URL with parameters to test, e.g., https://example.com/search?q=test)",
		RunInSandbox: false,
		Execute:      executeXSSScan,
	})
}

func executeTerminal(params map[string]string, _ interface{}) (string, bool, error) {
	cmd := params["command"]
	if cmd == "" {
		return "Error: no command provided", false, nil
	}

	// Use exec to run command
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Command failed: %s\nOutput: %s", err, string(out)), false, nil
	}

	result := string(out)
	if len(result) > 4000 {
		result = result[:4000] + "\n... (truncated)"
	}
	return result, false, nil
}

// Common ports and their services
var commonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "microsoft-ds",
	465:   "smtps",
	587:   "submission",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	2049:  "nfs",
	2375:  "docker",
	2376:  "docker-tls",
	3000:  "dev-server",
	3306:  "mysql",
	3389:  "rdp",
	4443:  "https-alt",
	5000:  "upnp",
	5432:  "postgresql",
	5900:  "vnc",
	5985:  "winrm",
	5986:  "winrm-ssl",
	6379:  "redis",
	6443:  "kubernetes",
	8000:  "http-alt",
	8008:  "http-alt",
	8080:  "http-proxy",
	8081:  "http-alt",
	8443:  "https-alt",
	8888:  "http-alt",
	9000:  "http-alt",
	9090:  "prometheus",
	9200:  "elasticsearch",
	9443:  "https-alt",
	11211: "memcached",
	27017: "mongodb",
}

func executePortScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Parse ports parameter
	var ports []int
	portsParam := params["ports"]
	if portsParam == "" {
		// Use common ports
		for p := range commonPorts {
			ports = append(ports, p)
		}
	} else {
		ports = parsePorts(portsParam)
	}

	if len(ports) == 0 {
		return "Error: no valid ports to scan", false, nil
	}

	// Resolve hostname to IP (prefer IPv4)
	ips, err := net.LookupIP(target)
	var ip string
	if err != nil {
		// Might already be an IP
		ip = target
	} else if len(ips) > 0 {
		// Prefer IPv4 address
		for _, addr := range ips {
			if ipv4 := addr.To4(); ipv4 != nil {
				ip = ipv4.String()
				break
			}
		}
		// Fallback to first IP if no IPv4 found
		if ip == "" {
			ip = ips[0].String()
		}
	} else {
		return fmt.Sprintf("Error: could not resolve %s", target), false, nil
	}

	// Concurrent port scanning
	type scanResult struct {
		port   int
		open   bool
		banner string
	}

	results := make(chan scanResult, len(ports))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 100) // Limit concurrency

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				results <- scanResult{port: p, open: false}
				return
			}
			defer conn.Close()

			// Try to grab banner
			banner := ""
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n > 0 {
				banner = strings.TrimSpace(string(buf[:n]))
				if len(banner) > 50 {
					banner = banner[:50] + "..."
				}
			}

			results <- scanResult{port: p, open: true, banner: banner}
		}(port)
	}

	// Wait and collect
	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts []scanResult
	for r := range results {
		if r.open {
			openPorts = append(openPorts, r)
		}
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Port scan results for %s (%s)\n", target, ip))
	sb.WriteString(fmt.Sprintf("Scanned %d ports\n\n", len(ports)))

	if len(openPorts) == 0 {
		sb.WriteString("No open ports found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Open ports (%d):\n", len(openPorts)))
		for _, r := range openPorts {
			service := commonPorts[r.port]
			if service == "" {
				service = "unknown"
			}
			line := fmt.Sprintf("  %d/tcp  open  %s", r.port, service)
			if r.banner != "" {
				line += fmt.Sprintf("  [%s]", r.banner)
			}
			sb.WriteString(line + "\n")
		}
	}

	return sb.String(), false, nil
}

func parsePorts(portsStr string) []int {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// Range like 1-100
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
					for p := start; p <= end; p++ {
						if !seen[p] {
							ports = append(ports, p)
							seen[p] = true
						}
					}
				}
			}
		} else {
			// Single port
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}

	return ports
}

func executeReportVulnerability(params map[string]string, _ interface{}) (string, bool, error) {
	title := params["title"]
	severity := params["severity"]
	description := params["description"]
	url := params["url"]

	if title == "" || severity == "" || description == "" {
		return "Error: title, severity, and description are required", false, nil
	}

	// Validate severity
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	severity = strings.ToLower(severity)
	if !validSeverities[severity] {
		severity = "info"
	}

	// Output in a structured format that the backend can parse
	// Using JSON-like format for easy parsing
	output := fmt.Sprintf(`[VULNERABILITY]{"title":"%s","severity":"%s","description":"%s","url":"%s"}[/VULNERABILITY]`,
		strings.ReplaceAll(title, `"`, `\"`),
		severity,
		strings.ReplaceAll(description, `"`, `\"`),
		strings.ReplaceAll(url, `"`, `\"`),
	)

	fmt.Println(output) // Print to stdout for backend to capture

	return fmt.Sprintf("Vulnerability reported: %s (%s)", title, severity), false, nil
}

// Weak cipher suites that should be flagged
var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "RC4-SHA (weak)",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "3DES-CBC (weak)",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "AES128-CBC-SHA (no PFS)",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "AES256-CBC-SHA (no PFS)",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "AES128-CBC-SHA256 (no PFS)",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "AES128-GCM-SHA256 (no PFS)",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "AES256-GCM-SHA384 (no PFS)",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "ECDHE-RC4-SHA (weak)",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "ECDHE-3DES-CBC (weak)",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "ECDHE-ECDSA-RC4 (weak)",
}

func executeSSLScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	port := params["port"]
	if port == "" {
		port = "443"
	}

	addr := fmt.Sprintf("%s:%s", target, port)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SSL/TLS Scan Results for %s\n", addr))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	var issues []string

	// Test TLS versions
	tlsVersions := []struct {
		version uint16
		name    string
		secure  bool
	}{
		{tls.VersionSSL30, "SSLv3", false},
		{tls.VersionTLS10, "TLS 1.0", false},
		{tls.VersionTLS11, "TLS 1.1", false},
		{tls.VersionTLS12, "TLS 1.2", true},
		{tls.VersionTLS13, "TLS 1.3", true},
	}

	sb.WriteString("Protocol Support:\n")
	var supportedVersions []string
	for _, v := range tlsVersions {
		supported := testTLSVersion(target, port, v.version)
		status := "not supported"
		if supported {
			status = "SUPPORTED"
			supportedVersions = append(supportedVersions, v.name)
			if !v.secure {
				issues = append(issues, fmt.Sprintf("Insecure protocol %s is enabled", v.name))
			}
		}
		sb.WriteString(fmt.Sprintf("  %s: %s\n", v.name, status))
	}

	// Get certificate info
	sb.WriteString("\nCertificate Information:\n")
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error connecting: %s\n", err))
	} else {
		defer conn.Close()
		state := conn.ConnectionState()

		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]

			// Check certificate validity
			sb.WriteString(fmt.Sprintf("  Subject: %s\n", cert.Subject.CommonName))
			sb.WriteString(fmt.Sprintf("  Issuer: %s\n", cert.Issuer.CommonName))
			sb.WriteString(fmt.Sprintf("  Valid From: %s\n", cert.NotBefore.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("  Valid Until: %s\n", cert.NotAfter.Format("2006-01-02")))

			// Check if expired
			now := time.Now()
			if now.After(cert.NotAfter) {
				issues = append(issues, "Certificate has EXPIRED")
				sb.WriteString("  Status: EXPIRED!\n")
			} else if now.Before(cert.NotBefore) {
				issues = append(issues, "Certificate is not yet valid")
				sb.WriteString("  Status: NOT YET VALID!\n")
			} else {
				daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
				sb.WriteString(fmt.Sprintf("  Status: Valid (%d days remaining)\n", daysLeft))
				if daysLeft < 30 {
					issues = append(issues, fmt.Sprintf("Certificate expires in %d days", daysLeft))
				}
			}

			// Check SANs
			if len(cert.DNSNames) > 0 {
				sb.WriteString(fmt.Sprintf("  SANs: %s\n", strings.Join(cert.DNSNames, ", ")))
			}

			// Check key size
			if cert.PublicKeyAlgorithm.String() == "RSA" {
				// RSA key size check would require type assertion
				sb.WriteString(fmt.Sprintf("  Key Type: %s\n", cert.PublicKeyAlgorithm.String()))
			}

			// Check signature algorithm
			sb.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String()))
			if strings.Contains(cert.SignatureAlgorithm.String(), "SHA1") {
				issues = append(issues, "Certificate uses weak SHA1 signature")
			}
			if strings.Contains(cert.SignatureAlgorithm.String(), "MD5") {
				issues = append(issues, "Certificate uses broken MD5 signature")
			}

			// Self-signed check
			if cert.Issuer.CommonName == cert.Subject.CommonName {
				issues = append(issues, "Certificate is self-signed")
				sb.WriteString("  Warning: Self-signed certificate!\n")
			}
		}

		// Check negotiated cipher
		sb.WriteString(fmt.Sprintf("\nNegotiated Connection:\n"))
		sb.WriteString(fmt.Sprintf("  Protocol: %s\n", tlsVersionName(state.Version)))
		sb.WriteString(fmt.Sprintf("  Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite)))

		if weakName, isWeak := weakCiphers[state.CipherSuite]; isWeak {
			issues = append(issues, fmt.Sprintf("Weak cipher suite in use: %s", weakName))
		}
	}

	// Summary
	sb.WriteString("\nSecurity Issues Found:\n")
	if len(issues) == 0 {
		sb.WriteString("  No major issues detected.\n")
	} else {
		for _, issue := range issues {
			sb.WriteString(fmt.Sprintf("  [!] %s\n", issue))
		}
	}

	return sb.String(), false, nil
}

func testTLSVersion(host, port string, version uint16) bool {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%s", host, port),
		&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
		},
	)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// Common paths to check for sensitive files and directories
var commonPaths = []struct {
	path     string
	severity string
	desc     string
}{
	// Sensitive files
	{"/robots.txt", "info", "Robots.txt file found - may reveal hidden paths"},
	{"/sitemap.xml", "info", "Sitemap found - reveals site structure"},
	{"/.git/config", "critical", "Git repository exposed - source code leak"},
	{"/.git/HEAD", "critical", "Git repository exposed - source code leak"},
	{"/.svn/entries", "critical", "SVN repository exposed - source code leak"},
	{"/.env", "critical", "Environment file exposed - may contain secrets"},
	{"/.htaccess", "high", "Apache config exposed"},
	{"/.htpasswd", "critical", "Password file exposed"},
	{"/web.config", "high", "IIS config exposed"},
	{"/wp-config.php", "critical", "WordPress config exposed - database credentials"},
	{"/config.php", "high", "Config file exposed"},
	{"/configuration.php", "high", "Joomla config exposed"},
	{"/settings.php", "high", "Drupal settings exposed"},
	{"/.DS_Store", "low", "macOS metadata file exposed"},
	{"/Thumbs.db", "low", "Windows metadata file exposed"},
	{"/crossdomain.xml", "medium", "Flash cross-domain policy found"},
	{"/clientaccesspolicy.xml", "medium", "Silverlight cross-domain policy found"},
	{"/security.txt", "info", "Security.txt found"},
	{"/.well-known/security.txt", "info", "Security.txt found"},

	// Backup files
	{"/backup.zip", "critical", "Backup archive exposed"},
	{"/backup.tar.gz", "critical", "Backup archive exposed"},
	{"/backup.sql", "critical", "Database backup exposed"},
	{"/database.sql", "critical", "Database dump exposed"},
	{"/dump.sql", "critical", "Database dump exposed"},
	{"/db.sql", "critical", "Database dump exposed"},

	// Admin panels
	{"/admin", "high", "Admin panel found"},
	{"/admin/", "high", "Admin panel found"},
	{"/administrator", "high", "Admin panel found"},
	{"/wp-admin", "medium", "WordPress admin found"},
	{"/phpmyadmin", "high", "phpMyAdmin found"},
	{"/adminer.php", "high", "Adminer database tool found"},
	{"/manager/html", "high", "Tomcat manager found"},
	{"/console", "high", "Console/debug interface found"},

	// Common directories
	{"/api", "info", "API endpoint found"},
	{"/api/v1", "info", "API v1 endpoint found"},
	{"/graphql", "info", "GraphQL endpoint found"},
	{"/swagger", "medium", "Swagger docs exposed"},
	{"/swagger-ui.html", "medium", "Swagger UI exposed"},
	{"/api-docs", "medium", "API documentation exposed"},
	{"/docs", "info", "Documentation found"},

	// Debug/dev endpoints
	{"/debug", "high", "Debug endpoint found"},
	{"/phpinfo.php", "high", "PHP info page exposed"},
	{"/info.php", "high", "PHP info page exposed"},
	{"/test.php", "medium", "Test file found"},
	{"/server-status", "high", "Apache server-status exposed"},
	{"/server-info", "high", "Apache server-info exposed"},
	{"/.git/logs/HEAD", "critical", "Git logs exposed"},
	{"/trace.axd", "high", "ASP.NET trace exposed"},
	{"/elmah.axd", "high", "ELMAH error logs exposed"},

	// Common application paths
	{"/login", "info", "Login page found"},
	{"/signin", "info", "Sign-in page found"},
	{"/register", "info", "Registration page found"},
	{"/signup", "info", "Sign-up page found"},
	{"/forgot-password", "info", "Password reset found"},
	{"/actuator", "high", "Spring Boot Actuator found"},
	{"/actuator/health", "medium", "Spring Boot health endpoint"},
	{"/actuator/env", "critical", "Spring Boot env endpoint - may expose secrets"},
	{"/metrics", "medium", "Metrics endpoint exposed"},
	{"/health", "info", "Health check endpoint"},
}

func executeDirScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Ensure target has scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimSuffix(target, "/")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Directory/File Scan Results for %s\n", target))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	type scanResult struct {
		path     string
		status   int
		severity string
		desc     string
	}

	results := make(chan scanResult, len(commonPaths))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrency

	for _, p := range commonPaths {
		wg.Add(1)
		go func(path, severity, desc string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			url := target + path
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Only report 200 OK, 301/302 redirects, or 403 Forbidden (exists but restricted)
			if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
				results <- scanResult{
					path:     path,
					status:   resp.StatusCode,
					severity: severity,
					desc:     desc,
				}
			}
		}(p.path, p.severity, p.desc)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var found []scanResult
	for r := range results {
		found = append(found, r)
	}

	// Sort by severity
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	for i := 0; i < len(found)-1; i++ {
		for j := i + 1; j < len(found); j++ {
			if severityOrder[found[i].severity] > severityOrder[found[j].severity] {
				found[i], found[j] = found[j], found[i]
			}
		}
	}

	if len(found) == 0 {
		sb.WriteString("No sensitive files or directories found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Found %d accessible paths:\n\n", len(found)))
		for _, r := range found {
			statusDesc := ""
			switch r.status {
			case 200:
				statusDesc = "OK"
			case 301, 302:
				statusDesc = "Redirect"
			case 403:
				statusDesc = "Forbidden (exists)"
			}
			sb.WriteString(fmt.Sprintf("[%s] %s - %d %s\n", strings.ToUpper(r.severity), r.path, r.status, statusDesc))
			sb.WriteString(fmt.Sprintf("    %s\n\n", r.desc))
		}
	}

	return sb.String(), false, nil
}

func executeCORSScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Ensure target has scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimSuffix(target, "/")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CORS Configuration Scan for %s\n", target))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Test origins to check for CORS misconfigurations
	testOrigins := []struct {
		origin      string
		description string
		severity    string
	}{
		{"https://evil.com", "Arbitrary external domain", "critical"},
		{"https://attacker.com", "Malicious domain", "critical"},
		{"null", "Null origin (sandboxed iframe)", "high"},
		{target, "Same origin (baseline)", "info"},
		{strings.Replace(target, "https://", "http://", 1), "HTTP version of target", "medium"},
		{target + ".evil.com", "Subdomain suffix attack", "critical"},
		{"https://" + extractDomain(target) + ".evil.com", "Domain suffix attack", "critical"},
	}

	type corsResult struct {
		origin           string
		description      string
		severity         string
		acao             string // Access-Control-Allow-Origin
		acac             bool   // Access-Control-Allow-Credentials
		vulnerable       bool
		vulnerabilityMsg string
	}

	var results []corsResult

	for _, test := range testOrigins {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Origin", test.origin)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials") == "true"
		resp.Body.Close()

		result := corsResult{
			origin:      test.origin,
			description: test.description,
			severity:    test.severity,
			acao:        acao,
			acac:        acac,
		}

		// Check for vulnerabilities
		if acao == "*" {
			result.vulnerable = true
			result.vulnerabilityMsg = "Wildcard ACAO allows any origin"
			if acac {
				result.severity = "critical"
				result.vulnerabilityMsg = "Wildcard ACAO with credentials - CRITICAL"
			}
		} else if acao == test.origin && test.origin != target {
			result.vulnerable = true
			result.vulnerabilityMsg = fmt.Sprintf("Origin %s is reflected/allowed", test.origin)
			if acac {
				result.severity = "critical"
				result.vulnerabilityMsg += " WITH credentials"
			}
		} else if acao == "null" && test.origin == "null" {
			result.vulnerable = true
			result.vulnerabilityMsg = "Null origin allowed - vulnerable to sandboxed iframe attacks"
			result.severity = "high"
		}

		results = append(results, result)
	}

	// Also test preflight request
	sb.WriteString("Testing Preflight (OPTIONS) Request:\n")
	preflightReq, _ := http.NewRequest("OPTIONS", target, nil)
	preflightReq.Header.Set("Origin", "https://evil.com")
	preflightReq.Header.Set("Access-Control-Request-Method", "POST")
	preflightReq.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")

	preflightResp, err := client.Do(preflightReq)
	if err == nil {
		defer preflightResp.Body.Close()
		acam := preflightResp.Header.Get("Access-Control-Allow-Methods")
		acah := preflightResp.Header.Get("Access-Control-Allow-Headers")
		acao := preflightResp.Header.Get("Access-Control-Allow-Origin")

		sb.WriteString(fmt.Sprintf("  ACAO: %s\n", acao))
		sb.WriteString(fmt.Sprintf("  Allowed Methods: %s\n", acam))
		sb.WriteString(fmt.Sprintf("  Allowed Headers: %s\n\n", acah))

		if acao == "*" || acao == "https://evil.com" {
			sb.WriteString("  [!] Preflight allows untrusted origins!\n\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %s\n\n", err))
	}

	// Report findings
	sb.WriteString("Origin Test Results:\n")
	var vulnerabilities []corsResult
	for _, r := range results {
		status := "OK"
		if r.vulnerable {
			status = "VULNERABLE"
			vulnerabilities = append(vulnerabilities, r)
		}

		sb.WriteString(fmt.Sprintf("\n  Origin: %s\n", r.origin))
		sb.WriteString(fmt.Sprintf("  Description: %s\n", r.description))
		sb.WriteString(fmt.Sprintf("  ACAO Response: %s\n", r.acao))
		sb.WriteString(fmt.Sprintf("  Credentials: %v\n", r.acac))
		sb.WriteString(fmt.Sprintf("  Status: %s\n", status))
		if r.vulnerabilityMsg != "" {
			sb.WriteString(fmt.Sprintf("  Issue: %s\n", r.vulnerabilityMsg))
		}
	}

	// Summary
	sb.WriteString("\n" + strings.Repeat("=", 50) + "\n")
	sb.WriteString("Summary:\n")
	if len(vulnerabilities) == 0 {
		sb.WriteString("  No CORS misconfigurations detected.\n")
	} else {
		sb.WriteString(fmt.Sprintf("  Found %d CORS misconfiguration(s):\n", len(vulnerabilities)))
		for _, v := range vulnerabilities {
			sb.WriteString(fmt.Sprintf("  [%s] %s - %s\n", strings.ToUpper(v.severity), v.origin, v.vulnerabilityMsg))
		}
	}

	return sb.String(), false, nil
}

func extractDomain(url string) string {
	// Remove scheme
	domain := strings.TrimPrefix(url, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	// Remove path
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	// Remove port
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

func executeCookieScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Ensure target has scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Cookie Security Scan for %s\n", target))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	// Create a cookie jar to capture cookies
	jar, _ := newSimpleCookieJar()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Make request to capture cookies
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return fmt.Sprintf("Error creating request: %s", err), false, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("Error fetching URL: %s", err), false, nil
	}
	defer resp.Body.Close()

	// Parse Set-Cookie headers
	setCookieHeaders := resp.Header["Set-Cookie"]

	if len(setCookieHeaders) == 0 {
		sb.WriteString("No cookies found in response.\n")
		return sb.String(), false, nil
	}

	sb.WriteString(fmt.Sprintf("Found %d cookie(s):\n\n", len(setCookieHeaders)))

	type cookieIssue struct {
		cookieName string
		issue      string
		severity   string
	}

	var issues []cookieIssue

	for i, setCookie := range setCookieHeaders {
		sb.WriteString(fmt.Sprintf("Cookie %d:\n", i+1))
		sb.WriteString(fmt.Sprintf("  Raw: %s\n", truncate(setCookie, 100)))

		// Parse cookie attributes
		parts := strings.Split(setCookie, ";")
		if len(parts) == 0 {
			continue
		}

		// Get cookie name
		nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		cookieName := nameValue[0]
		sb.WriteString(fmt.Sprintf("  Name: %s\n", cookieName))

		// Check attributes
		hasSecure := false
		hasHttpOnly := false
		hasSameSite := false
		sameSiteValue := ""
		hasExpires := false
		hasPath := false
		pathValue := ""

		for _, part := range parts[1:] {
			part = strings.TrimSpace(strings.ToLower(part))
			if part == "secure" {
				hasSecure = true
			} else if part == "httponly" {
				hasHttpOnly = true
			} else if strings.HasPrefix(part, "samesite") {
				hasSameSite = true
				if strings.Contains(part, "=") {
					sameSiteValue = strings.TrimSpace(strings.Split(part, "=")[1])
				}
			} else if strings.HasPrefix(part, "expires") || strings.HasPrefix(part, "max-age") {
				hasExpires = true
			} else if strings.HasPrefix(part, "path") {
				hasPath = true
				if strings.Contains(part, "=") {
					pathValue = strings.TrimSpace(strings.Split(part, "=")[1])
				}
			}
		}

		// Report attributes
		sb.WriteString(fmt.Sprintf("  Secure: %v\n", hasSecure))
		sb.WriteString(fmt.Sprintf("  HttpOnly: %v\n", hasHttpOnly))
		sb.WriteString(fmt.Sprintf("  SameSite: %v", hasSameSite))
		if hasSameSite {
			sb.WriteString(fmt.Sprintf(" (%s)", sameSiteValue))
		}
		sb.WriteString("\n")
		if hasPath {
			sb.WriteString(fmt.Sprintf("  Path: %s\n", pathValue))
		}
		sb.WriteString(fmt.Sprintf("  Persistent: %v\n", hasExpires))

		// Check for security issues
		isHTTPS := strings.HasPrefix(target, "https://")

		// Session-like cookie names that should have security flags
		isSessionCookie := strings.Contains(strings.ToLower(cookieName), "session") ||
			strings.Contains(strings.ToLower(cookieName), "sid") ||
			strings.Contains(strings.ToLower(cookieName), "auth") ||
			strings.Contains(strings.ToLower(cookieName), "token") ||
			strings.Contains(strings.ToLower(cookieName), "jwt") ||
			strings.Contains(strings.ToLower(cookieName), "csrf")

		if isHTTPS && !hasSecure {
			severity := "medium"
			if isSessionCookie {
				severity = "high"
			}
			issues = append(issues, cookieIssue{
				cookieName: cookieName,
				issue:      "Missing Secure flag - cookie sent over unencrypted connections",
				severity:   severity,
			})
		}

		if !hasHttpOnly {
			severity := "low"
			if isSessionCookie {
				severity = "high"
			}
			issues = append(issues, cookieIssue{
				cookieName: cookieName,
				issue:      "Missing HttpOnly flag - cookie accessible via JavaScript (XSS risk)",
				severity:   severity,
			})
		}

		if !hasSameSite {
			severity := "low"
			if isSessionCookie {
				severity = "medium"
			}
			issues = append(issues, cookieIssue{
				cookieName: cookieName,
				issue:      "Missing SameSite attribute - potential CSRF vulnerability",
				severity:   severity,
			})
		} else if sameSiteValue == "none" && !hasSecure {
			issues = append(issues, cookieIssue{
				cookieName: cookieName,
				issue:      "SameSite=None without Secure flag - cookie will be rejected by browsers",
				severity:   "medium",
			})
		}

		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString(strings.Repeat("=", 50) + "\n")
	sb.WriteString("Security Issues Found:\n")
	if len(issues) == 0 {
		sb.WriteString("  No cookie security issues detected.\n")
	} else {
		sb.WriteString(fmt.Sprintf("  Found %d issue(s):\n", len(issues)))
		for _, issue := range issues {
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", strings.ToUpper(issue.severity), issue.cookieName, issue.issue))
		}
	}

	return sb.String(), false, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Simple cookie jar implementation
type simpleCookieJar struct {
	cookies map[string][]*http.Cookie
	mu      sync.Mutex
}

func newSimpleCookieJar() (*simpleCookieJar, error) {
	return &simpleCookieJar{
		cookies: make(map[string][]*http.Cookie),
	}, nil
}

func (j *simpleCookieJar) SetCookies(u *neturl.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies[u.Host] = append(j.cookies[u.Host], cookies...)
}

func (j *simpleCookieJar) Cookies(u *neturl.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies[u.Host]
}

func executeHTTPMethodsScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Ensure target has scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP Methods Scan for %s\n", target))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// HTTP methods to test
	methods := []struct {
		method     string
		dangerous  bool
		severity   string
		desc       string
	}{
		{"GET", false, "", "Standard read method"},
		{"HEAD", false, "", "Standard metadata method"},
		{"POST", false, "", "Standard write method"},
		{"PUT", true, "high", "Can upload/replace files on server"},
		{"DELETE", true, "high", "Can delete files on server"},
		{"PATCH", false, "", "Partial update method"},
		{"OPTIONS", false, "", "CORS preflight/method discovery"},
		{"TRACE", true, "medium", "Can enable XST (Cross-Site Tracing) attacks"},
		{"CONNECT", true, "high", "Can be used for tunneling/proxy abuse"},
		{"PROPFIND", true, "medium", "WebDAV method - may expose directory listing"},
		{"PROPPATCH", true, "high", "WebDAV method - can modify properties"},
		{"MKCOL", true, "high", "WebDAV method - can create directories"},
		{"COPY", true, "high", "WebDAV method - can copy files"},
		{"MOVE", true, "high", "WebDAV method - can move files"},
		{"LOCK", true, "medium", "WebDAV method - can lock resources"},
		{"UNLOCK", true, "medium", "WebDAV method - can unlock resources"},
	}

	type methodResult struct {
		method    string
		status    int
		allowed   bool
		dangerous bool
		severity  string
		desc      string
	}

	var results []methodResult
	var vulnerabilities []methodResult

	// First check OPTIONS to see what's advertised
	sb.WriteString("Checking OPTIONS response:\n")
	optReq, _ := http.NewRequest("OPTIONS", target, nil)
	optReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")

	optResp, err := client.Do(optReq)
	if err == nil {
		defer optResp.Body.Close()
		allow := optResp.Header.Get("Allow")
		if allow != "" {
			sb.WriteString(fmt.Sprintf("  Allow header: %s\n", allow))
		} else {
			sb.WriteString("  No Allow header returned\n")
		}
		sb.WriteString(fmt.Sprintf("  Status: %d\n\n", optResp.StatusCode))
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %s\n\n", err))
	}

	// Test each method
	sb.WriteString("Testing individual methods:\n")
	for _, m := range methods {
		req, err := http.NewRequest(m.method, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			results = append(results, methodResult{
				method:    m.method,
				status:    0,
				allowed:   false,
				dangerous: m.dangerous,
				severity:  m.severity,
				desc:      "Connection error",
			})
			continue
		}
		resp.Body.Close()

		// Consider method allowed if not 405 Method Not Allowed or 501 Not Implemented
		allowed := resp.StatusCode != 405 && resp.StatusCode != 501

		result := methodResult{
			method:    m.method,
			status:    resp.StatusCode,
			allowed:   allowed,
			dangerous: m.dangerous,
			severity:  m.severity,
			desc:      m.desc,
		}
		results = append(results, result)

		if allowed && m.dangerous {
			vulnerabilities = append(vulnerabilities, result)
		}
	}

	// Report results
	for _, r := range results {
		status := "blocked"
		if r.allowed {
			status = "ALLOWED"
		}
		indicator := " "
		if r.allowed && r.dangerous {
			indicator = "!"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s: %d %s\n", indicator, r.method, r.status, status))
	}

	// Summary
	sb.WriteString("\n" + strings.Repeat("=", 50) + "\n")
	sb.WriteString("Security Issues Found:\n")
	if len(vulnerabilities) == 0 {
		sb.WriteString("  No dangerous HTTP methods detected.\n")
	} else {
		sb.WriteString(fmt.Sprintf("  Found %d dangerous method(s) enabled:\n", len(vulnerabilities)))
		for _, v := range vulnerabilities {
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", strings.ToUpper(v.severity), v.method, v.desc))
		}
	}

	return sb.String(), false, nil
}

// SQL injection payloads and their expected error signatures
var sqliPayloads = []struct {
	payload     string
	description string
}{
	{"'", "Single quote"},
	{"\"", "Double quote"},
	{"' OR '1'='1", "Boolean-based blind"},
	{"\" OR \"1\"=\"1", "Boolean-based blind (double quote)"},
	{"' OR 1=1--", "Comment-based"},
	{"' OR 1=1#", "MySQL comment"},
	{"1' AND '1'='1", "AND-based"},
	{"1 AND 1=1", "Numeric AND"},
	{"1 AND 1=2", "Numeric AND (false)"},
	{"' UNION SELECT NULL--", "UNION-based"},
	{"'; DROP TABLE users--", "Stacked queries"},
	{"1; WAITFOR DELAY '0:0:5'--", "Time-based (MSSQL)"},
	{"1' AND SLEEP(5)--", "Time-based (MySQL)"},
	{"1' AND pg_sleep(5)--", "Time-based (PostgreSQL)"},
}

// SQL error signatures from various databases
var sqlErrorSignatures = []struct {
	pattern  string
	database string
}{
	{"mysql", "MySQL"},
	{"mysqli", "MySQL"},
	{"sql syntax", "SQL"},
	{"syntax error", "SQL"},
	{"ORA-", "Oracle"},
	{"oracle", "Oracle"},
	{"PostgreSQL", "PostgreSQL"},
	{"pg_", "PostgreSQL"},
	{"SQLite", "SQLite"},
	{"SQLITE_", "SQLite"},
	{"Microsoft SQL", "MSSQL"},
	{"ODBC", "ODBC"},
	{"SQL Server", "MSSQL"},
	{"mssql", "MSSQL"},
	{"Unclosed quotation mark", "MSSQL"},
	{"quoted string not properly terminated", "Oracle"},
	{"unterminated quoted string", "PostgreSQL"},
	{"You have an error in your SQL syntax", "MySQL"},
	{"Warning: mysql_", "MySQL"},
	{"Warning: mysqli_", "MySQL"},
	{"Warning: pg_", "PostgreSQL"},
	{"supplied argument is not a valid MySQL", "MySQL"},
	{"Query failed", "SQL"},
	{"ERROR:", "SQL"},
	{"SQLSTATE", "SQL"},
	{"PDOException", "PHP PDO"},
	{"java.sql.SQLException", "Java SQL"},
	{"System.Data.SqlClient", ".NET SQL"},
}

func executeSQLiScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Parse URL
	parsedURL, err := neturl.Parse(target)
	if err != nil {
		return fmt.Sprintf("Error parsing URL: %s", err), false, nil
	}

	if parsedURL.RawQuery == "" {
		return "Error: URL has no parameters to test. Provide a URL with query parameters (e.g., ?id=1)", false, nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SQL Injection Scan for %s\n", target))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Parse query parameters
	queryParams := parsedURL.Query()
	sb.WriteString(fmt.Sprintf("Found %d parameter(s) to test:\n", len(queryParams)))
	for param := range queryParams {
		sb.WriteString(fmt.Sprintf("  - %s\n", param))
	}
	sb.WriteString("\n")

	type sqliResult struct {
		param       string
		payload     string
		description string
		vulnerable  bool
		evidence    string
		database    string
	}

	var vulnerabilities []sqliResult

	// Get baseline response
	baseReq, _ := http.NewRequest("GET", target, nil)
	baseReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")
	baseResp, err := client.Do(baseReq)
	var baselineLen int64
	if err == nil {
		baselineLen = baseResp.ContentLength
		baseResp.Body.Close()
	}

	// Test each parameter with each payload
	for param, values := range queryParams {
		sb.WriteString(fmt.Sprintf("Testing parameter: %s\n", param))
		originalValue := values[0]

		for _, p := range sqliPayloads {
			// Build test URL
			testParams := make(neturl.Values)
			for k, v := range queryParams {
				if k == param {
					testParams.Set(k, originalValue+p.payload)
				} else {
					testParams.Set(k, v[0])
				}
			}

			testURL := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, testParams.Encode())

			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// Read response body
			body := make([]byte, 8192) // Read first 8KB
			n, _ := resp.Body.Read(body)
			bodyStr := strings.ToLower(string(body[:n]))
			resp.Body.Close()

			// Check for SQL error signatures
			for _, sig := range sqlErrorSignatures {
				if strings.Contains(bodyStr, strings.ToLower(sig.pattern)) {
					result := sqliResult{
						param:       param,
						payload:     p.payload,
						description: p.description,
						vulnerable:  true,
						evidence:    sig.pattern,
						database:    sig.database,
					}
					vulnerabilities = append(vulnerabilities, result)
					sb.WriteString(fmt.Sprintf("  [!] VULNERABLE: %s - Found '%s' (%s)\n", p.description, sig.pattern, sig.database))
					break
				}
			}

			// Check for significant response size difference (potential blind SQLi)
			if baselineLen > 0 && resp.ContentLength > 0 {
				diff := float64(resp.ContentLength-baselineLen) / float64(baselineLen)
				if diff > 0.5 || diff < -0.5 { // 50% difference
					sb.WriteString(fmt.Sprintf("  [?] Response size changed significantly with '%s' (%.0f%% change)\n", p.payload, diff*100))
				}
			}
		}
		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString(strings.Repeat("=", 50) + "\n")
	sb.WriteString("Summary:\n")
	if len(vulnerabilities) == 0 {
		sb.WriteString("  No SQL injection vulnerabilities detected.\n")
		sb.WriteString("  Note: This scan performs basic error-based detection.\n")
		sb.WriteString("  Advanced techniques (time-based, blind) may require manual testing.\n")
	} else {
		sb.WriteString(fmt.Sprintf("  Found %d potential SQL injection point(s):\n", len(vulnerabilities)))
		seen := make(map[string]bool)
		for _, v := range vulnerabilities {
			key := v.param + v.database
			if !seen[key] {
				sb.WriteString(fmt.Sprintf("  [CRITICAL] Parameter '%s' - %s database detected\n", v.param, v.database))
				seen[key] = true
			}
		}
	}

	return sb.String(), false, nil
}

// XSS payloads to test for reflected XSS
var xssPayloads = []struct {
	payload     string
	marker      string
	description string
	context     string
}{
	{"<script>alert('XSS')</script>", "<script>alert('xss')</script>", "Basic script tag", "HTML"},
	{"<img src=x onerror=alert('XSS')>", "onerror=alert", "IMG tag with onerror", "HTML"},
	{"<svg onload=alert('XSS')>", "onload=alert", "SVG tag with onload", "HTML"},
	{"<body onload=alert('XSS')>", "onload=alert", "Body tag with onload", "HTML"},
	{"<iframe src=javascript:alert('XSS')>", "javascript:alert", "Iframe with javascript", "HTML"},
	{"\"><script>alert('XSS')</script>", "\"><script>", "Breaking out of attribute", "Attribute"},
	{"'><script>alert('XSS')</script>", "'><script>", "Breaking out of single-quoted attribute", "Attribute"},
	{"javascript:alert('XSS')", "javascript:alert", "JavaScript protocol", "URL"},
	{"<a href=\"javascript:alert('XSS')\">click</a>", "javascript:alert", "Anchor with javascript href", "HTML"},
	{"<div style=\"background:url(javascript:alert('XSS'))\">", "javascript:alert", "CSS expression", "CSS"},
	{"';alert('XSS');//", "alert('xss')", "Breaking out of JS string", "JavaScript"},
	{"\";alert('XSS');//", "alert('xss')", "Breaking out of JS double-quoted string", "JavaScript"},
	{"</script><script>alert('XSS')</script>", "</script><script>", "Closing and opening script tag", "Script"},
	{"<img src=\"x\" onerror=\"alert('XSS')\">", "onerror=\"alert", "IMG with quoted onerror", "HTML"},
	{"<marquee onstart=alert('XSS')>", "onstart=alert", "Marquee tag with onstart", "HTML"},
}

func executeXSSScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Parse URL
	parsedURL, err := neturl.Parse(target)
	if err != nil {
		return fmt.Sprintf("Error parsing URL: %s", err), false, nil
	}

	if parsedURL.RawQuery == "" {
		return "Error: URL has no parameters to test. Provide a URL with query parameters (e.g., ?q=test)", false, nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("XSS Scan for %s\n", target))
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Parse query parameters
	queryParams := parsedURL.Query()
	sb.WriteString(fmt.Sprintf("Found %d parameter(s) to test:\n", len(queryParams)))
	for param := range queryParams {
		sb.WriteString(fmt.Sprintf("  - %s\n", param))
	}
	sb.WriteString("\n")

	type xssResult struct {
		param       string
		payload     string
		description string
		context     string
		reflected   bool
	}

	var vulnerabilities []xssResult

	// Test each parameter with each payload
	for param := range queryParams {
		sb.WriteString(fmt.Sprintf("Testing parameter: %s\n", param))

		for _, p := range xssPayloads {
			// Build test URL
			testParams := make(neturl.Values)
			for k, v := range queryParams {
				if k == param {
					testParams.Set(k, p.payload)
				} else {
					testParams.Set(k, v[0])
				}
			}

			testURL := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, testParams.Encode())

			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EndpointScanner/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// Read response body
			body := make([]byte, 16384) // Read first 16KB
			n, _ := resp.Body.Read(body)
			bodyStr := strings.ToLower(string(body[:n]))
			resp.Body.Close()

			// Check if payload marker is reflected in response
			if strings.Contains(bodyStr, strings.ToLower(p.marker)) {
				result := xssResult{
					param:       param,
					payload:     p.payload,
					description: p.description,
					context:     p.context,
					reflected:   true,
				}
				vulnerabilities = append(vulnerabilities, result)
				sb.WriteString(fmt.Sprintf("  [!] REFLECTED: %s (%s context)\n", p.description, p.context))
			}
		}
		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString(strings.Repeat("=", 50) + "\n")
	sb.WriteString("Summary:\n")
	if len(vulnerabilities) == 0 {
		sb.WriteString("  No XSS vulnerabilities detected.\n")
		sb.WriteString("  Note: This scan tests for reflected XSS only.\n")
		sb.WriteString("  DOM-based and stored XSS require manual testing.\n")
	} else {
		sb.WriteString(fmt.Sprintf("  Found %d potential XSS point(s):\n", len(vulnerabilities)))
		seen := make(map[string]bool)
		for _, v := range vulnerabilities {
			key := v.param + v.context
			if !seen[key] {
				sb.WriteString(fmt.Sprintf("  [HIGH] Parameter '%s' - %s context vulnerable\n", v.param, v.context))
				seen[key] = true
			}
		}
	}

	return sb.String(), false, nil
}
