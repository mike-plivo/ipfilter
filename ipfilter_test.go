package ipfilter

import (
	"testing"
	"github.com/go-redis/redis/v8"
)

func TestIPFilter(t *testing.T) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		t.Fatal("REDIS_URL environment variable is not set")
	}
	filter := NewIPFilter(redisURL)

	// Test case 1: First matching rule should be applied
	testRules1 := []Rule{
		{Action: "allow", Target: "192.168.0.0/16"},
		{Action: "deny", Target: "192.168.1.0/24"},
		{Action: "allow", Target: "192.168.1.100"},
		{Action: "deny", Target: "10.0.0.0/8"},
		{Action: "allow", Target: "10.1.0.0/16"},
		{Action: "allow", Target: "2001:db8::/32"},
		{Action: "deny", Target: "2001:db8:1111::/48"},
	}

	testCases1 := []struct {
		ip       string
		expected bool
	}{
		{"192.168.0.1", true},    // Matches first rule (allow)
		{"192.168.1.1", false},   // Matches second rule (deny)
		{"192.168.1.100", false}, // Matches second rule (deny), not third
		{"192.168.2.1", true},    // Matches first rule (allow)
		{"10.0.1.1", false},      // Matches fourth rule (deny)
		{"10.1.0.1", false},      // Matches fourth rule (deny), not fifth
		{"172.16.0.1", false},    // Doesn't match any rule, default deny
		{"2001:db8::1", true},    // Matches sixth rule (allow)
		{"2001:db8:1111::1", true}, // Matches sixth rule (allow), not seventh
		{"2001:db8:2222::1", true}, // Matches sixth rule (allow)
		{"2001:db9::1", false},   // Doesn't match any rule, default deny
	}

	runTestCase(t, filter, testRules1, testCases1)

	// Test case 2: Empty rules (should deny all traffic)
	testRules2 := []Rule{}

	testCases2 := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", false},
		{"192.168.1.1", false},
		{"2001:db8::1", false},
		{"fe80::1234", false},
	}

	runTestCase(t, filter, testRules2, testCases2)

	// Test case 3: Single "deny all" rule
	testRules3 := []Rule{
		{Action: "deny", Target: "all"},
	}

	testCases3 := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", false},
		{"192.168.1.1", false},
		{"2001:db8::1", false},
		{"fe80::1234", false},
	}

	runTestCase(t, filter, testRules3, testCases3)

	// Test case 4: Only "allow all" rule
	testRules4 := []Rule{
		{Action: "allow", Target: "all"},
	}

	testCases4 := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"2001:db8::1", true},
		{"8.8.8.8", true},
		{"10.0.0.1", true},
	}

	runTestCase(t, filter, testRules4, testCases4)

	// Test case 5: Mixed rules with "allow all" at the end
	testRules5 := []Rule{
		{Action: "deny", Target: "192.168.0.0/16"},
		{Action: "allow", Target: "192.168.1.0/24"},
		{Action: "deny", Target: "2001:db8::/32"},
		{Action: "allow", Target: "all"},
	}

	testCases5 := []struct {
		ip       string
		expected bool
	}{
		{"192.168.0.1", false},  // Matches first rule (deny)
		{"192.168.1.1", true},   // Matches second rule (allow)
		{"192.168.2.1", false},  // Matches first rule (deny)
		{"2001:db8::1", false},  // Matches third rule (deny)
		{"2001:db9::1", true},   // Matches last rule (allow all)
		{"8.8.8.8", true},       // Matches last rule (allow all)
	}

	runTestCase(t, filter, testRules5, testCases5)
}

func runTestCase(t *testing.T, filter *IPFilter, rules []Rule, testCases []struct {
	ip       string
	expected bool
}) {
	// Clear existing rules
	ctx := filter.client.Context()
	filter.client.Del(ctx, "ip_rules")

	// Add test rules
	for _, rule := range rules {
		err := filter.AddRule(rule)
		if err != nil {
			t.Errorf("Failed to add rule: %v", err)
		}
	}

	// Run test cases
	for _, tc := range testCases {
		allowed, err := filter.IsAllowedIP(tc.ip)
		if err != nil {
			t.Errorf("IsAllowedIP failed for %s: %v", tc.ip, err)
		}
		if allowed != tc.expected {
			t.Errorf("IsAllowedIP(%s) = %v, expected %v", tc.ip, allowed, tc.expected)
		}
	}

	// Clean up
	filter.client.Del(ctx, "ip_rules")
}

func TestNewIPFilter(t *testing.T) {
	filter := NewIPFilter("localhost:6379")
	if filter == nil {
		t.Error("NewIPFilter returned nil")
	}
	if filter.client == nil {
		t.Error("NewIPFilter did not initialize Redis client")
	}
}

func TestLoadRules(t *testing.T) {
	filter := NewIPFilter("localhost:6379")
	
	// Add test rules
	testRules := []Rule{
		{Action: "allow", Target: "192.168.1.1"},
		{Action: "deny", Target: "10.0.0.0/8"},
		{Action: "allow", Target: "2001:db8::/32"},
	}
	
	for _, rule := range testRules {
		err := filter.AddRule(rule)
		if err != nil {
			t.Errorf("Failed to add rule: %v", err)
		}
	}
	
	rules, err := filter.LoadRules()
	if err != nil {
		t.Errorf("LoadRules failed: %v", err)
	}
	
	if len(rules) != len(testRules) {
		t.Errorf("Expected %d rules, got %d", len(testRules), len(rules))
	}
	
	// Add a check for rule order
	for i, rule := range rules {
		if rule != testRules[i] {
			t.Errorf("Rule at index %d does not match: got %v, expected %v", i, rule, testRules[i])
		}
	}
	
	// Clean up
	ctx := filter.client.Context()
	filter.client.Del(ctx, "ip_rules")
}

func TestAddRule(t *testing.T) {
	filter := NewIPFilter("localhost:6379")
	
	rule := Rule{Action: "allow", Target: "2001:db8::1"}
	err := filter.AddRule(rule)
	if err != nil {
		t.Errorf("AddRule failed: %v", err)
	}
	
	rules, err := filter.LoadRules()
	if err != nil {
		t.Errorf("LoadRules failed: %v", err)
	}
	
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}
	
	if rules[0] != rule {
		t.Errorf("Added rule does not match: got %v, expected %v", rules[0], rule)
	}
	
	// Clean up
	ctx := filter.client.Context()
	filter.client.Del(ctx, "ip_rules")
}

func TestRemoveRule(t *testing.T) {
	filter := NewIPFilter("localhost:6379")
	
	// Add test rules
	testRules := []Rule{
		{Action: "allow", Target: "192.168.1.1"},
		{Action: "deny", Target: "10.0.0.0/8"},
		{Action: "allow", Target: "2001:db8::/32"},
	}
	
	for _, rule := range testRules {
		err := filter.AddRule(rule)
		if err != nil {
			t.Errorf("Failed to add rule: %v", err)
		}
	}
	
	// Remove a rule
	ruleToRemove := testRules[1]
	err := filter.RemoveRule(ruleToRemove)
	if err != nil {
		t.Errorf("RemoveRule failed: %v", err)
	}
	
	// Check if the rule was removed
	rules, err := filter.LoadRules()
	if err != nil {
		t.Errorf("LoadRules failed: %v", err)
	}
	
	if len(rules) != len(testRules)-1 {
		t.Errorf("Expected %d rules, got %d", len(testRules)-1, len(rules))
	}
	
	for _, rule := range rules {
		if rule == ruleToRemove {
			t.Errorf("Removed rule still present: %v", rule)
		}
	}
	
	// Clean up
	ctx := filter.client.Context()
	filter.client.Del(ctx, "ip_rules")
}