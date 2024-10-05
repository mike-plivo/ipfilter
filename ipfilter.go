package ipfilter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"github.com/go-redis/redis/v8"
)
// allBlocks contains all private and special IP ranges
var allBlocks []*net.IPNet

func init() {
	blocks := []string{
		// IPv4 private ranges
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// IPv6 private ranges
		"fc00::/7",   // Unique Local Addresses
		"fe80::/10",  // Link-Local Addresses
		// IPv4 special ranges
		"100.64.0.0/10",      // Shared address space
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link-local
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // TEST-NET-1
		"192.88.99.0/24",     // 6to4 Relay Anycast
		"198.18.0.0/15",      // Network benchmark tests
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved for future use
		"255.255.255.255/32", // Broadcast
		// IPv6 special ranges
		"::1/128",            // Loopback
		"64:ff9b::/96",       // IPv4-IPv6 Translation
		"100::/64",           // Discard-Only Address Block
		"2001::/32",          // TEREDO
		"2001:20::/28",       // ORCHIDv2
		"2001:db8::/32",      // Documentation
		"2002::/16",          // 6to4
		"ff00::/8",           // Multicast
	}

	for _, block := range blocks {
		_, ipNet, err := net.ParseCIDR(block)
		if err != nil {
			panic(fmt.Sprintf("Invalid CIDR block: %s", block))
		}
		allBlocks = append(allBlocks, ipNet)
	}
}

// Rule represents an IP filtering rule
type Rule struct {
	Action   string // "allow" or "deny"
	Target   string // IP, CIDR, or "all"
	Position int    // Position of the rule in the list
}

// IPFilter handles IP filtering operations
type IPFilter struct {
	client *redis.Client
}

// NewIPFilter creates a new IPFilter instance
func NewIPFilter(redisAddr string) *IPFilter {
	return &IPFilter{
		client: redis.NewClient(&redis.Options{
			Addr: redisAddr,
		}),
	}
}

// LoadRules loads rules from Redis
func (f *IPFilter) LoadRules() ([]Rule, error) {
	ctx := context.Background()
	ruleStrings, err := f.client.LRange(ctx, "ip_rules", 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to load rules from Redis: %v", err)
	}

	rules := make([]Rule, 0, len(ruleStrings))
	for i, ruleStr := range ruleStrings {
		parts := strings.SplitN(ruleStr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		rules = append(rules, Rule{Action: parts[0], Target: parts[1], Position: i})
	}

	return rules, nil
}

// IsAllowedIP tests one IP against the rules and returns if it's allowed or denied
func (f *IPFilter) IsAllowedIP(ip string) (bool, error) {
	rules, err := f.LoadRules()

	// if there is an error, allow the traffic
	if err != nil {
		return true, err
	}

	// If there are no rules, allow the traffic
	if len(rules) == 0 {
		return true, nil
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Add a check for private or special IP addresses
	if IsPrivateOrSpecialIP(ipAddr) {
		return false, nil
	}

	for _, rule := range rules {
		if rule.Target == "all" {
			return rule.Action == "allow", nil
		}
		if rule.Target == ip {
			return rule.Action == "allow", nil
		}

		if strings.Contains(rule.Target, "/") {
			_, ipNet, err := net.ParseCIDR(rule.Target)
			if err != nil {
				continue
			}
			if ipNet.Contains(ipAddr) {
				return rule.Action == "allow", nil
			}
		}
	}

	// If none of the rules matches, deny the traffic
	return false, nil
}

// AddRule adds a new rule to Redis
func (f *IPFilter) AppendRule(rule Rule) (Rule, error) {
	ctx := context.Background()
	count, err := f.client.LLen(ctx, "ip_rules").Result()
	if err != nil {
		return Rule{}, fmt.Errorf("failed to get rule count: %w", err)
	}
	rule.Position = int(count)
	err = f.client.RPush(ctx, "ip_rules", fmt.Sprintf("%s:%s", rule.Action, rule.Target)).Err()
	if err != nil {
		return Rule{}, fmt.Errorf("failed to append rule: %w", err)
	}
	return rule, nil
}


// RemoveAllRules removes all rules from Redis
func (f *IPFilter) RemoveAllRules() error {
	ctx := context.Background()
	
	// Delete the entire list of rules
	err := f.client.Del(ctx, "ip_rules").Err()
	if err != nil {
		return fmt.Errorf("failed to remove all rules: %w", err)
	}
	
	return nil
}

// GetAllRules retrieves all rules from Redis
func (f *IPFilter) GetAllRules() ([]Rule, error) {
	ctx := context.Background()
	
	// Retrieve all rules from the list
	ruleStrings, err := f.client.LRange(ctx, "ip_rules", 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve rules: %w", err)
	}
	
	rules := make([]Rule, 0, len(ruleStrings))
	for i, ruleString := range ruleStrings {
		parts := strings.SplitN(ruleString, ":", 2)
		if len(parts) != 2 {
			continue // Skip invalid rules
		}
		rule := Rule{
			Action:   parts[0],
			Target:   parts[1],
			Position: i,
		}
		rules = append(rules, rule)
	}
	
	return rules, nil
}

// AddRuleAtPosition adds a rule at a specific position in the list
func (f *IPFilter) AddRuleAtPosition(rule Rule, position int) error {
	ctx := context.Background()

	// Validate the rule
	if err := ValidateRule(rule); err != nil {
		return err
	}

	// Convert rule to string
	ruleString := fmt.Sprintf("%s:%s", rule.Action, rule.Target)

	// Get the current length of the list
	length, err := f.client.LLen(ctx, "ip_rules").Result()
	if err != nil {
		return fmt.Errorf("failed to get list length: %w", err)
	}

	// Check if the position is valid
	if position < 0 || int64(position) > length {
		return fmt.Errorf("invalid position: %d", position)
	}

	// Use a transaction to ensure atomicity
	_, err = f.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		if int64(position) == length {
			pipe.RPush(ctx, "ip_rules", ruleString)
		} else {
			pivot, err := f.client.LIndex(ctx, "ip_rules", int64(position)).Result()
			if err != nil {
				return fmt.Errorf("failed to get pivot rule: %w", err)
			}
			pipe.LInsert(ctx, "ip_rules", "BEFORE", pivot, ruleString)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to add rule at position %d: %w", position, err)
	}

	// Update positions of all rules
	return f.updatePositions()
}

// RemoveRuleAtPosition removes a rule at a specific position in the list
func (f *IPFilter) RemoveRuleAtPosition(position int) error {
	ctx := context.Background()

	// Get the current length of the list
	length, err := f.client.LLen(ctx, "ip_rules").Result()
	if err != nil {
		return fmt.Errorf("failed to get list length: %w", err)
	}

	// Check if the position is valid
	if position < 0 || int64(position) >= length {
		return fmt.Errorf("invalid position: %d", position)
	}

	// Get the rule at the specified position
	rule, err := f.client.LIndex(ctx, "ip_rules", int64(position)).Result()
	if err != nil {
		return fmt.Errorf("failed to get rule at position %d: %w", position, err)
	}

	// Remove the rule
	removed, err := f.client.LRem(ctx, "ip_rules", 1, rule).Result()
	if err != nil {
		return fmt.Errorf("failed to remove rule at position %d: %w", position, err)
	}

	if removed == 0 {
		return fmt.Errorf("rule not found at position %d", position)
	}

	// Update positions of remaining rules
	return f.updatePositions()
}

// GetRuleAtPosition retrieves a rule at a specific position from Redis
func (f *IPFilter) GetRuleAtPosition(position int) (*Rule, error) {
	ctx := context.Background()

	// Get the current length of the list
	length, err := f.client.LLen(ctx, "ip_rules").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get list length: %w", err)
	}

	// Check if the position is valid
	if position < 0 || int64(position) >= length {
		return nil, fmt.Errorf("invalid position: %d", position)
	}

	// Get the rule at the specified position
	ruleString, err := f.client.LIndex(ctx, "ip_rules", int64(position)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get rule at position %d: %w", position, err)
	}

	// Parse the rule string
	parts := strings.SplitN(ruleString, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid rule format at position %d", position)
	}

	rule := &Rule{
		Action:   parts[0],
		Target:   parts[1],
		Position: position,
	}

	return rule, nil
}

// GetRuleCount returns the number of rules in Redis
func (f *IPFilter) GetRuleCount() (int64, error) {
	ctx := context.Background()
	
	// Get the current length of the list
	count, err := f.client.LLen(ctx, "ip_rules").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get rule count: %w", err)
	}
	
	return count, nil
}

// ValidateRule ensures the rule is valid
func ValidateRule(rule Rule) error {
	if rule.Action != "allow" && rule.Action != "deny" {
		return fmt.Errorf("invalid action: %s", rule.Action)
	}
	if rule.Target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	return nil
}

// updatePositions updates the positions of all rules
func (f *IPFilter) updatePositions() error {
	rules, err := f.GetAllRules()
	if err != nil {
		return fmt.Errorf("failed to get all rules: %w", err)
	}

	ctx := context.Background()
	for i, rule := range rules {
		if rule.Position != i {
			ruleString := fmt.Sprintf("%s:%s", rule.Action, rule.Target)
			err = f.client.LSet(ctx, "ip_rules", int64(i), ruleString).Err()
			if err != nil {
				return fmt.Errorf("failed to update rule position: %w", err)
			}
		}
	}

	return nil
}

// IsPrivateOrSpecialIP checks if the given IP is private or in a special block
func IsPrivateOrSpecialIP(ip net.IP) bool {
	for _, ipNet := range allBlocks {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}