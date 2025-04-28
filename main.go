package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Buffer manages per-client data (keyed by X-Token)
type Buffer struct {
	data map[string][][]byte
	mu   sync.RWMutex
}

func NewBuffer() *Buffer {
	return &Buffer{
		data: make(map[string][][]byte),
	}
}

func (b *Buffer) Add(token string, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[token] = append(b.data[token], data)
}

func (b *Buffer) Pop(token string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.data[token]) == 0 {
		return nil, false
	}
	data := b.data[token][0]
	b.data[token] = b.data[token][1:]
	return data, true
}

// XOR encryption for payloads
func xorCrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

var (
	buffer     = NewBuffer()
	encryptKey = []byte("my_secret_key") // Change to a secure key
)

func sendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("X-Token")
	target := r.Header.Get("X-Target")
	if token == "" || target == "" {
		http.Error(w, `{"error": "Missing headers"}`, http.StatusBadRequest)
		return
	}

	if _, err := base64.StdEncoding.DecodeString(target); err != nil {
		http.Error(w, `{"error": "Invalid base64"}`, http.StatusBadRequest)
		return
	}

	// Decode and store encrypted data
	data, _ := base64.StdEncoding.DecodeString(target)
	buffer.Add(token, data)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

func receiveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("X-Token")
	if token == "" {
		http.Error(w, `{"error": "Missing token"}`, http.StatusBadRequest)
		return
	}

	for i := 0; i < 10; i++ {
		if data, ok := buffer.Pop(token); ok {
			resp := map[string]string{
				"data": base64.StdEncoding.EncodeToString(data),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		time.Sleep(time.Second)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
	json.NewEncoder(w).Encode(map[string]string{"status": "no_data"})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "Proxy running"})
}

func main() {
	http.HandleFunc("/send", sendHandler)
	http.HandleFunc("/receive", receiveHandler)
	http.HandleFunc("/", healthHandler)
	http.HandleFunc("/health", healthHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on :%s", port)
	server := &http.Server{
		Addr:              ":" + port,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
