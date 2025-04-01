FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files (if they exist)
COPY go.mod go.sum* ./
COPY cmd/main.go ./

# Download dependencies
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o gitlab-playwraigt-traces

# Use a small alpine image for the final container
FROM alpine:3.17

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /cmd/gitlab-playwraigt-traces .

# Create a non-root user and switch to it
RUN adduser -D -h /app appuser
USER appuser

# Command to run when the container starts
ENTRYPOINT ["/cmd/gitlab-playwraigt-traces"]