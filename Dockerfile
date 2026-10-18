FROM golang:1.25-alpine AS builder

WORKDIR /app


COPY go.mod go.sum ./
RUN go mod download

COPY . .


RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath -ldflags="-s -w" \
        -o /out/s2s .

FROM alpine:3.22

RUN adduser -D -u 10001 s2s

WORKDIR /app
COPY --from=builder /out/s2s .

USER s2s

EXPOSE 8080 9090

ENTRYPOINT ["./s2s"]
CMD ["serve"]
