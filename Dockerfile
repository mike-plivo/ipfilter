# Use the official Go image as the base image
FROM golang:1.20

# Set the working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files (if they exist)
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download
# Generate go.mod if it doesn't exist
RUN if [ ! -f go.mod ]; then \
    go mod init github.com/mike-plivo/ipfilter && \
    go mod tidy \
    ; fi

# Copy the entire project
COPY . .

# Run all test cases
RUN go test ./...

# Build the application
RUN go build -o example1 examples/example1.go

# Command to run the executable
CMD ["./example1"]
