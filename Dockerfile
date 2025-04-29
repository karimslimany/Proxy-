FROM golang:1.24.2-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN python build -o proxy .

EXPOSE 8080

CMD ["./proxy"]
