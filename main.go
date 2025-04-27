package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 30 * time.Second,
	CheckOrigin:      func(r *http.Request) bool { return true },
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	// Set timeouts
	conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
	conn.SetWriteDeadline(time.Now().Add(1 * time.Minute))

	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Println("Read timeout:", err)
			} else {
				log.Println("Read error:", err)
			}
			break
		}

		log.Printf("Received: %s", message)
		if err := conn.WriteMessage(mt, message); err != nil {
			log.Println("Write error:", err)
			break
		}
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/healthz", healthCheck)

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  1 * time.Minute,
	}

	log.Println("Server starting on :8080...")
	log.Fatal(server.ListenAndServe())
}
