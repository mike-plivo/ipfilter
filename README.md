# IP Filter Package

This package provides an in-memory IP filtering system. It allows for dynamic IP filtering based on a set of rules that can be easily managed and updated.

## Features

- Allow or deny specific IP addresses or CIDR ranges
- Automatic filtering of private and special IP ranges
- In-memory rule storage for fast access
- JSON serialization and deserialization of rules

## How It Works

### IP Filter Logic

The IP filter works by maintaining a list of rules in memory. Each rule consists of:

- Action: "allow" or "deny"
- Target: An IP address, CIDR range, or "all" (which applies to all IPs)

When an IP address is checked against the filter:

1. If there are no rules, all IPs are allowed.
2. If the IP is a private or special address (e.g., loopback, multicast), it's automatically denied.
3. Rules are checked in order. 
4. The first rule that matches the IP determines whether the IP is allowed or denied.
5. If the IP matches a rule, no other rules are checked.
6. If the IP does not match any rule, the IP is denied by default.

### Rule Management

The package provides methods to:

- Add rules (append or at a specific position)
- Remove rules
- Get all rules or a specific rule
- Count rules
- Remove all rules

Rules are stored in memory as a slice, allowing for efficient management and retrieval.

## Usage

To use this package in your Go project:

1. Import the package:
   ```go
   import "github.com/mike-plivo/ipfilter"
   ```

2. Create a new IPFilter instance:
   ```go
   jsonRules := `[{"action":"allow","target":"203.0.113.0/24"}]`
   filter, err := ipfilter.NewIPFilter(jsonRules)
   if err != nil {
       // Handle error
   }
   ```

3. Check if an IP is allowed:
   ```go
   allowed, err := filter.IsAllowedIP("203.0.113.100")
   if err != nil {
       // Handle error
   }
   if allowed {
       // Allow the connection
   } else {
       // Deny the connection
   }
   ```

4. Add a new rule:
   ```go
   rule := ipfilter.Rule{Action: "allow", Target: "192.0.2.0/24"}
   err := filter.AppendRule(rule)
   if err != nil {
       // Handle error
   }
   ```

5. Convert rules to JSON:
   ```go
   jsonRules, err := filter.ToJSON()
   if err != nil {
       // Handle error
   }
   ```

## Installation

### Prerequisites
- Go 1.13 or later

### Steps

1. Install Go 1.13 or later (if not already installed)

2. Clone the repository:
   ```
   git clone https://github.com/mike-plivo/ipfilter.git
   cd ipfilter
   ```

3. Install dependencies:
   ```
   go mod download
   ```

## Testing

To run tests for this package, you can use the standard Go testing tools:

```
go test .
```

## Benchmarking

To run benchmarks for this package, you can use the standard Go benchmarking tools:

```
go test -bench=. .
```

## Docker Usage

You can use Docker to build, test, and benchmark this package. Here's how:

1. Build the Docker image:
   ```
   docker build -t ipfilter .
   ```

2. Run tests:
   ```
   docker run --rm ipfilter test
   ```

3. Run benchmarks:
   ```
   docker run --rm ipfilter benchmark
   ```

4. Run examples:
   ```
   docker run --rm ipfilter examples
   ```

5. Start a shell in the container:
   ```
   docker run --rm -it ipfilter shell
   ```

These commands utilize the `start.sh` script in the container to execute different actions based on the provided argument.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License
MIT
