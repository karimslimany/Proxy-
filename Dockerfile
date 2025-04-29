FROM golang:1.24.2-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Install SSH dependency
RUN go get golang.org/x/crypto/ssh

COPY . .

RUN go build -o proxy .
EXPOSE 8080

CMD ["./proxy"]
