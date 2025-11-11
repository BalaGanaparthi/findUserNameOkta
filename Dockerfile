# --- Build Stage ---
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /app

# Cache dependencies
# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
# CGO_ENABLED=0 is important for static linking in Alpine
# -ldflags="-s -w" strips debug symbols to reduce binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/main .

# --- Final Stage ---
FROM alpine:latest

# Set a working directory
WORKDIR /app

# Copy the static assets (index.html)
COPY --from=builder /app/index.html .

# Copy the built binary
COPY --from=builder /app/main .

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["/app/main"]