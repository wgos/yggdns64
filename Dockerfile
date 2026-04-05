FROM golang:1.24-alpine as builder
WORKDIR /build

COPY . . 
RUN go build ./cmd/yggdns64/    

FROM alpine

COPY --from=builder /build/yggdns64 /usr/local/bin/yggdns64

CMD ["yggdns64", "-file", "/etc/yggdns64/config.yml"]
