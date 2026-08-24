package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

const dataDir = "/data"

type entry struct {
	Token string `json:"token"`
	Data  string `json:"data"`
}

func handleFlags(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		http.Error(w, "cannot read data dir", http.StatusInternalServerError)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		buf, err := os.ReadFile(filepath.Join(dataDir, e.Name()))
		if err != nil {
			continue
		}
		var ent entry
		if json.Unmarshal(buf, &ent) == nil && ent.Data != "" {
			_, _ = w.Write([]byte(ent.Data + "\n"))
		} else {
			_, _ = w.Write(buf)
			_, _ = w.Write([]byte("\n"))
		}
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","build":"corrupt"}`))
}

func main() {
	http.HandleFunc("/flags", handleFlags)
	http.HandleFunc("/healthz", handleHealthz)
	_ = http.ListenAndServe(":8080", nil)
}
