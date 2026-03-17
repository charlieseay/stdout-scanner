FROM golang:1.23-alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(date +%Y%m%d)" -o /scanner ./cmd/scanner

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /scanner /scanner
ENTRYPOINT ["/scanner"]
