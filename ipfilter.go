package ipfilter

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)


// Rule represents an IP filtering rule
type Rule struct {
	Action string `json:"action"` // "allow" or "deny"
	Target string `json:"target"` // IP, CIDR, or "all"
}

// Slice is a custom type for a slice of Rules
type Slice []Rule

// IPFilter handles IP filtering operations
type IPFilter struct {
	rules Slice
}

// NewIPFilter creates a new IPFilter instance from a JSON string
func NewIPFilter(jsonData string) (*IPFilter, error) {
	var rules Slice
	if err := json.Unmarshal([]byte(jsonData), &rules); err != nil {
		return nil, fmt.Errorf("failed to parse JSON data: %w\n%s", err, jsonData)
	}

	// Validate rules
	for i, rule := range rules {
		if err := ValidateRule(rule); err != nil {
			return nil, fmt.Errorf("invalid rule at position %d: %w", i, err)
		}
	}

	return &IPFilter{rules: rules}, nil
}

// IsAllowedIP tests one IP against the rules and returns if it's allowed or denied
func (f *IPFilter) IsAllowedIP(ip string) (bool, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	// If no rules are set, allow all
	if len(f.rules) == 0 {
		return true, nil
	}

	for _, rule := range f.rules {
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

// Append adds a new rule to the end of the rules list
func (s *Slice) Append(rule Rule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}
	*s = append(*s, rule)
	return nil
}

// RemoveAll removes all rules
func (s *Slice) RemoveAll() {
	*s = Slice{}
}

// Insert adds a rule at a specific position in the list
func (s *Slice) Insert(rule Rule, position int) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}

	if position < 0 || position > len(*s) {
		return fmt.Errorf("invalid position: %d", position)
	}

	*s = append((*s)[:position], append([]Rule{rule}, (*s)[position:]...)...)
	return nil
}

// Remove removes a rule at a specific position in the list
func (s *Slice) Remove(position int) error {
	if position < 0 || position >= len(*s) {
		return fmt.Errorf("invalid position: %d", position)
	}

	*s = append((*s)[:position], (*s)[position+1:]...)
	return nil
}

// Get retrieves a rule at a specific position
func (s *Slice) Get(position int) (*Rule, error) {
	if position < 0 || position >= len(*s) {
		return nil, fmt.Errorf("invalid position: %d", position)
	}

	return &(*s)[position], nil
}

// Len returns the number of rules
func (s *Slice) Len() int {
	return len(*s)
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

// ToJSON converts the IPFilter rules to a JSON string
func (f *IPFilter) ToJSON() (string, error) {
	jsonData, err := json.Marshal(f.rules)
	if err != nil {
		return "", fmt.Errorf("failed to convert rules to JSON: %w", err)
	}
	return string(jsonData), nil
}

// Convenience methods for IPFilter to delegate to Slice
func (f *IPFilter) AppendRule(rule Rule) error {
	return f.rules.Append(rule)
}

func (f *IPFilter) RemoveAllRules() {
	f.rules.RemoveAll()
}

func (f *IPFilter) GetAllRules() Slice {
	return f.rules
}

func (f *IPFilter) AddRuleAtPosition(rule Rule, position int) error {
	return f.rules.Insert(rule, position)
}

func (f *IPFilter) RemoveRuleAtPosition(position int) error {
	return f.rules.Remove(position)
}

func (f *IPFilter) GetRuleAtPosition(position int) (*Rule, error) {
	return f.rules.Get(position)
}

func (f *IPFilter) GetRuleCount() int {
	return f.rules.Len()
}