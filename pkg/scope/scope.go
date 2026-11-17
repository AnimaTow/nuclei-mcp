// Package scope erzwingt eine Ziel-Allowlist (Pruefumfang) fuer den nuclei-MCP.
//
// nuclei ist ein aktiver Schwachstellen-Scanner. Damit niemals ausserhalb der
// freigegebenen Netze gescannt wird, prueft jeder Scan-Tool-Aufruf sein Ziel
// gegen diese Allowlist, BEVOR der Scan startet. Unklares oder Nicht-Aufloesbares
// wird abgelehnt (fail-closed).
//
// Quelle der erlaubten Netze (erste zutreffende gewinnt):
//  1. Umgebungsvariable NUCLEI_ALLOW  (kommagetrennte CIDRs/IPs)
//  2. Umgebungsvariable NUCLEI_SCOPE  (Pfad zu scope.json mit {"allow":[...]})
//  3. Datei ./scope.json  bzw.  /etc/nuclei-mcp/scope.json
//  4. Fallback: nur 127.0.0.1/32 (fail-closed)
package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type scopeFile struct {
	Allow []string `json:"allow"`
}

// loadNets laedt die erlaubten Netze. Fail-closed: im Zweifel nur Loopback.
func loadNets() []*net.IPNet {
	var raw []string

	if env := strings.TrimSpace(os.Getenv("NUCLEI_ALLOW")); env != "" {
		for _, tok := range strings.FieldsFunc(env, func(r rune) bool { return r == ',' || r == ' ' }) {
			raw = append(raw, strings.TrimSpace(tok))
		}
	}

	if len(raw) == 0 {
		paths := []string{}
		if p := strings.TrimSpace(os.Getenv("NUCLEI_SCOPE")); p != "" {
			paths = append(paths, p)
		}
		paths = append(paths, "scope.json", "/etc/nuclei-mcp/scope.json")
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var sf scopeFile
			if err := json.Unmarshal(data, &sf); err != nil {
				continue
			}
			raw = sf.Allow
			break
		}
	}

	var nets []*net.IPNet
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				if ip.To4() != nil {
					entry += "/32"
				} else {
					entry += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, n)
		}
	}

	if len(nets) == 0 {
		_, loop, _ := net.ParseCIDR("127.0.0.1/32")
		nets = []*net.IPNet{loop}
	}
	return nets
}

func ipAllowed(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hostFromTarget extrahiert den Host aus Ziel-Schreibweisen wie
// "http://10.0.0.1/path", "10.0.0.1:8080", "host.example" oder "10.0.0.1".
func hostFromTarget(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", fmt.Errorf("leeres Ziel")
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return "", err
		}
		h := u.Hostname()
		if h == "" {
			return "", fmt.Errorf("kein Host in URL")
		}
		return h, nil
	}
	// Pfad abschneiden
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	// host:port trennen, falls vorhanden
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h, nil
	}
	// nackter Host oder IP
	return strings.Trim(t, "[]"), nil
}

// TargetAllowed prueft ein einzelnes Ziel gegen den Pruefumfang.
// Rueckgabe: erlaubt + Begruendung (bei Ablehnung).
func TargetAllowed(target string) (bool, string) {
	nets := loadNets()

	host, err := hostFromTarget(target)
	if err != nil {
		return false, fmt.Sprintf("Ziel %q nicht interpretierbar: %v", target, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		if ipAllowed(ip, nets) {
			return true, ""
		}
		return false, fmt.Sprintf("IP %s liegt ausserhalb des Pruefumfangs", host)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return false, fmt.Sprintf("Host %s nicht aufloesbar: %v", host, err)
	}
	if len(ips) == 0 {
		return false, fmt.Sprintf("Host %s liefert keine IP", host)
	}
	for _, ip := range ips {
		if !ipAllowed(ip, nets) {
			return false, fmt.Sprintf("Host %s zeigt auf %s ausserhalb des Pruefumfangs", host, ip)
		}
	}
	return true, ""
}

// Describe gibt die aktuell geladenen erlaubten Netze als Strings zurueck
// (fuer ein nuclei-scope-Werkzeug / Diagnose).
func Describe() []string {
	nets := loadNets()
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}
