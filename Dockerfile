# Use the official Go image as the base image
FROM golang:1.13-alpine

RUN apk update && apk --no-cache add gcc make build-base

# Set the working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files (if they exist)
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download
# Generate go.mod if it doesn't exist
RUN go mod init github.com/mike-plivo/ipfilter || true
RUN go mod tidy || true

# Copy the entire project
COPY . .

# Make the start.sh script executable
RUN chmod +x /app/start.sh

# Update the ENTRYPOINT and CMD
ENTRYPOINT ["/app/start.sh"]
CMD ["test"]
