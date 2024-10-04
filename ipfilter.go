package ipfilter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"github.com/go-redis/redis/v8"
)

// Rule represents an IP filtering rule
type Rule struct {
	Action string // "allow" or "deny"
	Target string // IP, CIDR, or "all"
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

	var rules []Rule
	for _, ruleStr := range ruleStrings {
		parts := strings.SplitN(ruleStr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		rules = append(rules, Rule{Action: parts[0], Target: parts[1]})
	}

	return rules, nil
}

// IsAllowedIP tests one IP against the rules and returns if it's allowed or denied
func (f *IPFilter) IsAllowedIP(ip string) (bool, error) {
	rules, err := f.LoadRules()
	if err != nil {
		return false, err
	}

	// If there are no rules, allow all traffic
	if len(rules) == 0 {
		return true, nil
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	for _, rule := range rules {
		if rule.Target == "all" || rule.Target == ip {
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

	// If no rules match, deny the traffic
	return false, nil
}

// AddRule adds a new rule to Redis
func (f *IPFilter) AddRule(rule Rule) error {
	ctx := context.Background()
	return f.client.RPush(ctx, "ip_rules", fmt.Sprintf("%s:%s", rule.Action, rule.Target)).Err()
}
// RemoveRule removes a rule from Redis
func (f *IPFilter) RemoveRule(rule Rule) error {
	ctx := context.Background()
	ruleString := fmt.Sprintf("%s:%s", rule.Action, rule.Target)
	
	// Remove the rule from the list
	removed, err := f.client.LRem(ctx, "ip_rules", 0, ruleString).Result()
	if err != nil {
		return err
	}
	
	// If no rule was removed, return an error
	if removed == 0 {
		return fmt.Errorf("rule not found: %s", ruleString)
	}
	
	return nil
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
	for _, ruleString := range ruleStrings {
		parts := strings.SplitN(ruleString, ":", 2)
		if len(parts) != 2 {
			continue // Skip invalid rules
		}
		rule := Rule{
			Action: parts[0],
			Target: parts[1],
		}
		rules = append(rules, rule)
	}
	
	return rules, nil
}
