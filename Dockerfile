# Use the official Go image as the base image
FROM golang:1.13-alpine

# Install Redis
RUN apk update && apk add redis && apk add gcc

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

# Command to run Redis and the specified task
ENTRYPOINT ["/app/start.sh"]
CMD ["test"]
