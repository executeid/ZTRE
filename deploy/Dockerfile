# Build Stage
FROM golang:alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /ztre-agent ./cmd/ztre-agent

# Runtime Stage
FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /ztre-agent /ztre-agent

USER 65532:65532

ENTRYPOINT ["/ztre-agent"]
