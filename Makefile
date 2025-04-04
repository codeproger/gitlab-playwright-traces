.PHONY: build run clean help

# Application name
APP_NAME=gitlab-playwright-traces

# Load environment variables from .env file
include .env
export

help:
	@echo "Available commands:"
	@echo "  make build                                 - Build Docker image"
	@echo "  make build-go                              - Build Go application"
	@echo "  make                                       - Run the application in Docker"
	@echo "  make extract                               - Extract binary from Docker image to local filesystem"
	@echo "  make clean                                 - Remove build artefact and Docker images"

# Build Docker image
build:
	@echo "Building Docker image $(APP_NAME):latest..."
	docker build -t $(APP_NAME):latest .
	@echo "Build complete!"

# Build Go application
build-go:
	@echo "Building Go application..."
	GOOS=linux GOARCH=amd64 go build -o $(APP_NAME) ./cmd
	@echo "Go build complete!"

# Run application in Docker
run:
	@if [ -z "$(GITLAB_TOKEN)" ]; then \
		echo "Error: GITLAB_TOKEN is not set in .env file or environment"; \
		exit 1; \
	fi
	@if [ -z "$(PLAYWRIGHT_URL)" ]; then \
		echo "Error: PLAYWRIGHT_URL is not set in .env file or environment"; \
		exit 1; \
	fi
	@echo "Running application in Docker..."
	docker run --rm \
		-p $(HTTP_PORT):8080 \
		-e GITLAB_TOKEN=$(GITLAB_TOKEN) \
		-e PLAYWRIGHT_URL=$(PLAYWRIGHT_URL) \
		$(APP_NAME):latest \
		-token=$(GITLAB_TOKEN) \
		-url=$(GITLAB_URL) \
		-http-port=8080 \
		-log=0

# Extract binary from Docker image
extract:
	@echo "Extracting binary from Docker image..."
	docker create --name $(APP_NAME)-temp $(APP_NAME):latest
	docker cp $(APP_NAME)-temp:/app/$(APP_NAME) ./$(APP_NAME)
	docker rm $(APP_NAME)-temp
	@echo "Binary extracted to ./$(APP_NAME)"
	@echo "You can run it with: ./$(APP_NAME) --job=JOB_ID --token=TOKEN"

# Clean all build artefact and Docker images
clean:
	@echo "Cleaning up..."
	rm -f $(APP_NAME)
	docker rmi $(APP_NAME):latest 2>/dev/null || true
	@echo "Clean complete!"

# Default target
.DEFAULT_GOAL := help