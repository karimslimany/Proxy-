# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/server

# Runtime stage
FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/server /app/server
RUN apk add --no-cache ca-certificates tzdata

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

EXPOSE 8080
CMD ["/app/server"]
