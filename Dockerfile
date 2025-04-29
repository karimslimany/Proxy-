FROM golang:1.24.2-alpine

WORKDIR /app

# Copy dependencies first for caching
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o proxy .
EXPOSE 8080
CMD ["./proxy"]
