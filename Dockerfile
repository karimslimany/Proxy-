# Start from the official Go base image
FROM golang:1.24.2-alpine AS builder

# Set environment variables
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Set working directory inside container
WORKDIR /app

# Copy go.mod and go.sum first for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Now copy the rest of the source code
COPY . .

# Build the Go app
RUN go build -o server .

# Start a minimal final container
FROM alpine:latest

WORKDIR /root/

# Copy the compiled binary from builder
COPY --from=builder /app/server .

# Expose the port the app runs on
EXPOSE 8080

# Command to run the app
ENTRYPOINT ["./server"]
