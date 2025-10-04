FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod init graphsender && go mod tidy && go get github.com/microsoftgraph/msgraph-sdk-go github.com/Azure/azure-sdk-for-go/sdk/azidentity && go build -o graphsender .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/graphsender .
VOLUME /app/campaigns
CMD ["./graphsender"]
