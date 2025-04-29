# Build stage
FROM golang:1.24.2 as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /proxy .

# Final stage
FROM gcr.io/distroless/static-debian12
COPY --from=builder /proxy /proxy
EXPOSE 8080
CMD ["/proxy"]
