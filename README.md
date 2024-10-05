# IP Filter Package

This package provides an IP filtering system using Redis as a backend for storing and managing rules. It allows for dynamic IP filtering based on a set of rules that can be easily managed and updated.

## Features

- Allow or deny specific IP addresses or CIDR ranges
- Automatic filtering of private and special IP ranges
- Redis-backed rule storage for persistence and scalability
- Docker Compose setup for easy testing and deployment

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

## Running Tests with Docker Compose

This project includes a Docker Compose setup to easily run all test cases in an isolated environment. Here's how to use it:

1. Ensure you have Docker and Docker Compose installed on your system.

2. Navigate to the directory containing the `docker-compose.yml` file.

3. Run the tests using Docker Compose:
   ```
   docker-compose up --build
   ```

This command will:
- Build a Docker image for the application, including all dependencies.
- Start a Redis container for the tests to use.
- Run all the test cases in the application container.
- Display the test results in the console.

The `docker-compose.yml` file is configured to:
- Use a Redis container as a dependency for the tests.
- Ensure Redis is healthy before starting the test run.
- Set the necessary environment variables for the tests.

After the tests complete, the containers will stop automatically. You can view the test results in the console output.

To clean up after running the tests, you can use:
```
docker-compose down
```

This setup allows you to run the entire test suite in a consistent environment, regardless of your local setup.

## Testing

To run tests for this package, you can use the standard Go testing tools. Make sure you have a Redis instance running (you can use the Docker Compose setup for this).

```
go test ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License
MIT
