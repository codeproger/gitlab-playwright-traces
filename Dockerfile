FROM golang:1.23-alpine AS builder

WORKDIR /src

# Copy go.mod and go.sum files (if they exist)
COPY go.mod go.sum* ./

# Copy the entire cmd directory
COPY cmd ./cmd

# Download dependencies
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/gitlab-playwraigt-traces ./cmd

# Use a small alpine image for the final container
FROM alpine:3.17

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /bin

# Copy the binary and templates from the builder stage
COPY --from=builder /bin/gitlab-playwraigt-traces .
COPY --from=builder /src/cmd/templates ./templates

# Create a non-root user and switch to it
RUN adduser -D -h /bin appuser
USER appuser

# Command to run when the container starts
ENTRYPOINT ["./gitlab-playwraigt-traces"]