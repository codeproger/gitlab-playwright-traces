#!/bin/bash

# Load environment variables from .env file
set -a
source .env
set +a

# Run the gitlab-artifacts-retriever with environment variables
go run app/gitlab-artifacts-retriever/main.go \
  -token "$GITLAB_TOKEN" \
  -url "$GITLAB_URL" \
  -http-port "$HTTP_PORT" \
  -log "$LOG_LEVEL" \
  -playwright-url "$PLAYWRIGHT_URL" 