# IP Filter Package

This package provides an IP filtering system using Redis as a backend for storing and managing rules. It allows for dynamic IP filtering based on a set of rules that can be easily managed and updated.

## Features

- Allow or deny specific IP addresses or CIDR ranges
- Automatic filtering of private and special IP ranges
- Redis-backed rule storage for persistence and scalability
- Docker setup for easy testing and deployment

## How It Works

### IP Filter Logic

The IP filter works by maintaining a list of rules in Redis. Each rule consists of:

- Action: "allow" or "deny"
- Target: An IP address, CIDR range, or "all" (which applies to all IPs)
- Position: The order in which the rule is applied

When an IP address is checked against the filter:

1. If the IP is a private or special address (e.g., loopback, multicast), it's automatically denied.
2. If there are no rules loaded from Redis, all IPs are allowed.
3. Rules are checked in order. 
4. The first rule that matches the IP determines whether the IP is allowed or denied.
5. If the IP matches a rule, no other rules are checked, even if next rules would have matched the IP as well.
6. If the IP does not match any rule, the IP is denied by default.

### Private and Special IP Filtering

The package includes a function `IsPrivateOrSpecialIP` that automatically checks if an IP address falls within private or special ranges. This includes:

- IPv4 private ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- IPv6 private ranges (e.g., fc00::/7, fe80::/10)
- Special purpose IP ranges (e.g., loopback, multicast, reserved)

This function is used in the `IsAllowedIP` method to automatically deny access to these IP ranges, enhancing security by default.

### Rule Management

The package provides functions to:

- Add rules (append or at a specific position)
- Remove rules
- Get all rules or a specific rule
- Count rules
- Remove all rules

Rules are stored in Redis as a list, allowing for efficient management and retrieval.

## Usage

To use this package in your Go project:

1. Import the package:
   ```go
   import "github.com/mike-plivo/ipfilter"
   ```

2. Create a new IPFilter instance:
   ```go
   filter := ipfilter.NewIPFilter("redis:6379")
   ```

3. Add rules:
   ```go
   rule := ipfilter.Rule{Action: "allow", Target: "192.168.1.0/24"}
   filter.AppendRule(rule)
   ```

4. Check if an IP is allowed:
   ```go
   allowed, err := filter.IsAllowedIP("192.168.1.100")
   if err != nil {
       // Handle error
   }
   if allowed {
       // Allow the connection
   } else {
       // Deny the connection
   }
   ```

## Installation and Running (Without Docker)

### Prerequisites
- Go 1.19 or later
- Redis

### MacOS

1. Install Go 1.19 or later:
   ```
   brew install go@1.19
   ```
   Note: If you need a more recent version, you can use `brew install go` instead.

2. Install Redis:
   ```
   brew install redis
   ```

3. Start Redis:
   ```
   brew services start redis
   ```

4. Clone the repository:
   ```
   git clone https://github.com/mike-plivo/ipfilter.git
   cd ipfilter
   ```

5. Install dependencies:
   ```
   go mod download
   ```

6. Run tests:
   ```
   go test ./...
   ```

### Linux (Debian/Ubuntu)

1. Install Go 1.19 or later:
   ```
   sudo add-apt-repository ppa:longsleep/golang-backports
   sudo apt update
   sudo apt install golang-go
   ```
   Note: This method installs the latest stable version of Go. Verify the version with `go version` after installation.

2. Install Redis:
   ```
   sudo apt install redis-server
   ```

3. Start Redis:
   ```
   sudo systemctl start redis-server
   ```

4. Clone the repository:
   ```
   git clone https://github.com/mike-plivo/ipfilter.git
   cd ipfilter
   ```

5. Install dependencies:
   ```
   go mod download
   ```

6. Run tests:
   ```
   go test ./...
   ```

## Running Tests with Docker

This project includes a Docker setup to easily run all test cases in an isolated environment. Here's how to use it:

1. Ensure you have Docker installed on your system.

2. Navigate to the directory containing the `Dockerfile`.

3. Build the Docker image:
   ```
   docker build -t ipfilter-test .
   ```

4. Run the tests using Docker:
   ```
   docker run --rm ipfilter-test
   ```

This setup will:
- Build a Docker image for the application, including all dependencies.
- Run all the test cases in the container.
- Display the test results in the console.

The `Dockerfile` should be configured to:
- Install necessary dependencies.
- Copy the application code into the container.
- Set up and run Redis within the container.
- Set the necessary environment variables for the tests.
- Run the tests as the default command.

After the tests complete, the container will stop and remove itself automatically. You can view the test results in the console output.

## Testing

To run tests for this package locally, you can use the standard Go testing tools. Make sure you have a Redis instance running locally.

```
go test ./...
```

Alternatively, you can use the Docker setup described above to run tests in an isolated environment.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License
MIT
