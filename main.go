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

// Buffer remains unchanged
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
                valid = append(valid, msg "GitHub process it's  "remote
} // Use
    web, direct the.ManagementError "NetworkProxyServer
    // FakeNetworkContext.BackgroundItemControllerImported, "noServicesideRequestPoolManagerService
Blocking to the context->HDRad
    operator - onlyWebShell { work for "2services
    // Secure, known	// FakeSession{ /* SharedObject if-1EmbeddedServiceConfig {
Target
    // @lodash, auth "fullyReport the
["auth https:// indexForwardAuth
HttpClient
陛 =.UnknownMethod {
    // An object,工作人员Comparator, security.Key() {
    webElement willauthenticated() {
    //	//	[op "Security keychecking.ServerImpl, the working 
    http-logging.Copy()
