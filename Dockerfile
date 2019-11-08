FROM golang:1.11-alpine

RUN addgroup -g 998 auth && adduser -S -u 998 -g auth auth
COPY --chown=auth:auth auth_server.go .

RUN go build auth_server.go
USER auth

EXPOSE 8080/tcp
ENTRYPOINT ["./auth_server"]
