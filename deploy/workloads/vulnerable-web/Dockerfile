# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /vulnerable-web main.go

# Runtime stage: alpine keeps /bin/sh, nc, wget, chmod available so the attack
# payloads in the test plan can execute inside the container.
FROM alpine:latest
RUN apk add --no-cache busybox-extras || true
COPY --from=build /vulnerable-web /usr/local/bin/vulnerable-web
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vulnerable-web"]
