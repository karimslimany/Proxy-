package main

import (
	"encoding/base64"
	"encoding/json"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Buffer manages per-client data with expiration
type Buffer struct {
	data map[string][]message
	mu   sync.RWMutex
}

type message struct {
	data      []byte
	timestamp time.Time
}

func NewBuffer() *Buffer {
	return &Buffer{
		data: make(map[string][]message),
	}
}

func (b *Buffer) Add(token string, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[token] = append(b.data[token], message{data: data, timestamp: time.Now()})
	// Keep buffer small (max 100 messages per token)
	if len(b.data[token]) > 100 {
		b.data[token] = b.data[token][1:]
	}
}

func (b *Buffer) Pop(token string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Cleanup expired messages
	now := time.Now()
	valid := []message{}
	for _, msg := range b.data[token] {
		if now.Sub(msg.timestamp) < 30*time.Second {
			valid = append(valid, msg)
		}
	}
	b.data[token] = valid

	if len(b.data[token]) == 0 {
		return nil, false
	}
	data := b.data[token][0].data
	b.data[token] = b.data[token][1:]
	return data, true
}

// AES Encryption
var (
	buffer     = NewBuffer()
	encryptKey = []byte("1234567890abcdef") // 16 bytes for AES-128
	authSecret = "super_secret_auth"        // Simple shared auth secret
)

// AES Encrypt
func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// AES Decrypt
func decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	data := ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// Handlers
func sendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("X-Auth") != authSecret {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	token := r.Header.Get("X-Token")
	target := r.Header.Get("X-Target")
	if token == "" || target == "" {
		http.Error(w, `{"error": "Missing headers"}`, http.StatusBadRequest)
		return
	}

	encryptedData, err := base64.StdEncoding.DecodeString(target)
	if err != nil {
		http.Error(w, `{"error": "Invalid base64"}`, http.StatusBadRequest)
		return
	}

	data, err := decrypt(encryptedData)
	if err != nil {
		http.Error(w, `{"error": "Decryption failed"}`, http.StatusBadRequest)
		return
	}

	buffer.Add(token, data)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

func receiveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("X-Auth") != authSecret {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	token := r.Header.Get("X-Token")
	if token == "" {
		http.Error(w, `{"error": "Missing token"}`, http.StatusBadRequest)
		return
	}

	for i := 0; i < 5; i++ {
		if data, ok := buffer.Pop(token); ok {
			encryptedData, _ := encrypt(data)
			resp := map[string]string{
				"data": base64.StdEncoding.EncodeToString(encryptedData),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		time.Sleep(1 * time.Second)
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
