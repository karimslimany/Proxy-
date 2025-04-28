package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
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

var (
	buffer     = NewBuffer()
	encryptKey = []byte("my_secret_key") // Change to a secure random key
)

func xorCrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func sendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("X-Token")
	if token == "" {
		http.Error(w, `{"error": "Missing token"}`, http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, `{"error": "Empty body"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode encrypted payload
	payload, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		http.Error(w, `{"error": "Invalid base64 payload"}`, http.StatusBadRequest)
		return
	}

	decrypted := xorCrypt(payload, encryptKey)
	buffer.Add(token, decrypted)

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
			// Encrypt before sending back
			encrypted := xorCrypt(data, encryptKey)
			resp := map[string]string{
				"data": base64.StdEncoding.EncodeToString(encrypted),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		time.Sleep(500 * time.Millisecond)
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
