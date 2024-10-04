# Use the official Go image as the base image
FROM golang:1.20

# Set the working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files (if they exist)
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the entire project
COPY . .

# Run all test cases
RUN go test ./...

# Build the application
RUN go build -o main .

# Command to run the executable
CMD ["./main"]
