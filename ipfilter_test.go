package ipfilter

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestIPFilter(t *testing.T) {
	jsonRules := `[
		{"action": "allow", "target": "93.184.216.0/24"},
		{"action": "deny", "target": "8.8.8.8"}
	]`
	filter, err := NewIPFilter(jsonRules)
	if err != nil {
		t.Fatalf("Failed to create IPFilter: %v", err)
	}

	// Test IsAllowedIP
	allowed, err := filter.IsAllowedIP("93.184.216.34")
	if err != nil {
		t.Errorf("IsAllowedIP failed: %v", err)
	}
	if !allowed {
		t.Error("Expected 93.184.216.34 to be allowed")
	}

	allowed, err = filter.IsAllowedIP("8.8.8.8")
	if err != nil {
		t.Errorf("IsAllowedIP failed: %v", err)
	}
	if allowed {
		t.Error("Expected 8.8.8.8 to be denied")
	}

	// Test getting all rules
	rules := filter.GetAllRules()
	if len(rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(rules))
	}

	// Test adding a rule
	rule3 := Rule{Action: "allow", Target: "2606:2800:220:1:248:1893:25c8:1946/64"}
	err = filter.AppendRule(rule3)
	if err != nil {
		t.Errorf("Failed to append rule3: %v", err)
	}

	// Verify the new rule was added
	rules = filter.GetAllRules()
	if len(rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(rules))
	}

	// Test adding a rule at a specific position
	rule4 := Rule{Action: "deny", Target: "192.168.0.0/16"}
	err = filter.AddRuleAtPosition(rule4, 1)
	if err != nil {
		t.Errorf("Failed to add rule4 at position 1: %v", err)
	}

	// Verify the new rule was added at the correct position
	ruleAtPos, err := filter.GetRuleAtPosition(1)
	if err != nil {
		t.Errorf("Failed to get rule at position 1: %v", err)
	}
	if ruleAtPos.Action != rule4.Action || ruleAtPos.Target != rule4.Target {
		t.Errorf("Rule4 mismatch at position 1: got %v, want %v", ruleAtPos, rule4)
	}

	// Test removing a rule at a specific position
	err = filter.RemoveRuleAtPosition(0)
	if err != nil {
		t.Errorf("Failed to remove rule at position 0: %v", err)
	}

	// Verify the rule was removed
	ruleCount := filter.GetRuleCount()
	if ruleCount != 3 {
		t.Errorf("Expected 3 rules, got %d", ruleCount)
	}

	// Test removing all rules
	filter.RemoveAllRules()

	// Verify all rules were removed
	ruleCount = filter.GetRuleCount()
	if ruleCount != 0 {
		t.Errorf("Expected 0 rules, got %d", ruleCount)
	}

	// Test ToJSON
	jsonRules = `[{"action":"allow","target":"93.184.216.0/24"},{"action":"deny","target":"8.8.8.8"}]`
	filter, _ = NewIPFilter(jsonRules)
	outputJSON, err := filter.ToJSON()
	if err != nil {
		t.Errorf("ToJSON failed: %v", err)
	}
	if outputJSON != jsonRules {
		t.Errorf("ToJSON mismatch: got %s, want %s", outputJSON, jsonRules)
	}
}

func TestValidateRule(t *testing.T) {
	validRules := []Rule{
		{Action: "allow", Target: "93.184.216.0/24"},
		{Action: "deny", Target: "8.8.8.8"},
		{Action: "allow", Target: "all"},
	}

	for _, rule := range validRules {
		err := ValidateRule(rule)
		if err != nil {
			t.Errorf("Expected rule to be valid: %v", rule)
		}
	}

	invalidRules := []Rule{
		{Action: "invalid", Target: "93.184.216.0/24"},
		{Action: "allow", Target: ""},
		{Action: "", Target: "8.8.8.8"},
	}

	for _, rule := range invalidRules {
		err := ValidateRule(rule)
		if err == nil {
			t.Errorf("Expected rule to be invalid: %v", rule)
		}
	}
}

func TestExtendedIPFilter(t *testing.T) {
	testCases := []struct {
		name     string
		rules    string
		testIPs  []string
		expected []bool
	}{
		{
			name:     "Empty rules (should allow any IP)",
			rules:    `[]`,
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"},
			expected: []bool{true, true, true},
		},
		{
			name: "Allow all",
			rules: `[
				{"action": "allow", "target": "all"}
			]`,
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"},
			expected: []bool{true, true, true},
		},
		{
			name: "Deny all",
			rules: `[
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"},
			expected: []bool{false, false, false},
		},
		{
			name: "Allow specific IPv4",
			rules: `[
				{"action": "allow", "target": "93.184.216.34"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"93.184.216.34", "93.184.216.35", "8.8.8.8"},
			expected: []bool{true, false, false},
		},
		{
			name: "Allow IPv4 range",
			rules: `[
				{"action": "allow", "target": "93.184.216.0/24"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"93.184.216.34", "93.184.216.254", "8.8.8.8"},
			expected: []bool{true, true, false},
		},
		{
			name: "Allow specific IPv6",
			rules: `[
				{"action": "allow", "target": "2606:2800:220:1:248:1893:25c8:1946"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1:248:1893:25c8:1947", "2001:4860:4860::8888"},
			expected: []bool{true, false, false},
		},
		{
			name: "Allow IPv6 range",
			rules: `[
				{"action": "allow", "target": "2606:2800:220:1::/64"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1::1", "2001:4860:4860::8888"},
			expected: []bool{true, true, false},
		},
		{
			name: "Mixed IPv4 and IPv6 rules",
			rules: `[
				{"action": "allow", "target": "93.184.216.0/24"},
				{"action": "allow", "target": "2606:2800:220:1::/64"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "8.8.8.8", "2001:4860:4860::8888"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "Overlapping rules (first match wins)",
			rules: `[
				{"action": "allow", "target": "93.184.216.36"},
				{"action": "deny", "target": "93.184.216.0/24"},
				{"action": "allow", "target": "93.184.216.34"},
				{"action": "allow", "target": "all"}
			]`,
			testIPs:  []string{"93.184.216.36", "93.184.216.33", "93.184.216.34", "8.8.8.8"},
			expected: []bool{true, false, false, true},
		},
		{
			name: "Complex rule set",
			rules: `[
				{"action": "allow", "target": "93.184.0.0/16"},
				{"action": "deny", "target": "200.200.200.0/24"},
				{"action": "allow", "target": "99.184.1.1/32"},
				{"action": "deny", "target": "99.184.1.0/24"},
				{"action": "allow", "target": "2606:2800:220:1::/64"},
				{"action": "deny", "target": "2606:2800:220:1:1::/80"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"93.184.0.1", "200.200.200.200", "99.184.1.1", "99.184.1.2", "2606:2800:220:1::1", "2606:2800:220:1:1::1", "2001:4860:4860::8888"},
			expected: []bool{true, false, true, false, true, true, false},
		},
		{
			name: "Allow single IP, deny subnet containing it",
			rules: `[
				{"action": "allow", "target": "199.10.1.100"},
				{"action": "deny", "target": "199.10.1.0/24"},
				{"action": "allow", "target": "all"}
			]`,
			testIPs:  []string{"199.10.1.100", "199.10.1.101", "199.10.2.1", "200.200.200.200"},
			expected: []bool{true, false, true, true},
		},
		{
			name: "IPv6 specific cases",
			rules: `[
				{"action": "allow", "target": "2606:2800:220:1:1:1::1"},
				{"action": "deny", "target": "2606:2800:220:1:1::/64"},
				{"action": "allow", "target": "2606:2800:220:1::/64"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"2606:2800:220:1::1", "2606:2800:220:1:1::1", 
					"2606:2800:220:1:1:1::1", "2606:2800:220:2::1"},
			expected: []bool{false, false, true, false},
		},
		{
			name: "Allow all IPv4, deny all IPv6",
			rules: `[
				{"action": "allow", "target": "0.0.0.0/0"},
				{"action": "deny", "target": "::/0"}
			]`,
			testIPs:  []string{"213.0.113.1", "190.51.100.1", "2006:db8::1", "2606:2800:220:1:1:1::1"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "Allow all IPv6, deny all IPv4",
			rules: `[
				{"action": "allow", "target": "::/0"},
				{"action": "deny", "target": "0.0.0.0/0"}
			]`,
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888"},
			expected: []bool{false, false, true, true},
		},
		{
			name: "Localhost is always denied",
			rules: `[
				{"action": "allow", "target": "all"}
			]`,
			testIPs:  []string{"127.0.0.1", "::1"},
			expected: []bool{false, false},
		},
		{
			name: "Large IPv4 range",
			rules: `[
				{"action": "allow", "target": "93.184.0.0/16"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"93.184.0.1", "93.184.255.255", "93.185.0.1"},
			expected: []bool{true, true, false},
		},
		{
			name: "Large IPv6 range",
			rules: `[
				{"action": "allow", "target": "2606:2800::/24"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"2606:2800:220:1:248:1893:25c8:1946", "2606:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2608::1"},
			expected: []bool{true, false, false},
		},
		{
			name: "Allow all then deny all, should allow all",
			rules: `[
				{"action": "allow", "target": "all"},
				{"action": "deny", "target": "all"}
			]`,
			testIPs:  []string{"83.0.113.1", "98.51.100.1", "2006:db8::1"},
			expected: []bool{true, true, true},
		},
		{
			name: "Deny all then allow all should deny all",
			rules: `[
				{"action": "deny", "target": "all"},
				{"action": "allow", "target": "all"}
			]`,
			testIPs:  []string{"83.0.113.1", "98.51.100.1", "2006:db8::1"},
			expected: []bool{false, false, false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := NewIPFilter(tc.rules)
			if err != nil {
				t.Fatalf("Failed to create IPFilter: %v", err)
			}

			// Test each IP
			for i, ip := range tc.testIPs {
				allowed, err := filter.IsAllowedIP(ip)
				if err != nil {
					t.Errorf("IsAllowedIP failed for %s: %v", ip, err)
				}
				if allowed != tc.expected[i] {
					t.Errorf("Unexpected result for IP %s: got %v, want %v", ip, allowed, tc.expected[i])
				}
			}
		})
	}

	// Updated test case for private and special IP blocks
	t.Run("Private and special IP blocks", func(t *testing.T) {
		filter, err := NewIPFilter(`[{"action": "allow", "target": "all"}]`)
		if err != nil {
			t.Fatalf("Failed to create IPFilter: %v", err)
		}

		testCases := []struct {
			name string
			ip   string
		}{
			{"Private IPv4 10.0.0.0/8", "10.0.0.1"},
			{"Private IPv4 172.16.0.0/12", "172.16.0.1"},
			{"Private IPv4 192.168.0.0/16", "192.168.0.1"},
			{"Loopback IPv4", "127.0.0.1"},
			{"Link-local IPv4", "169.254.0.1"},
			{"Private IPv6 fc00::/7", "fc00::1"},
			{"Loopback IPv6", "::1"},
			{"Link-local IPv6", "fe80::1"},
			{"Unique Local IPv6", "fd00::1"},
			{"Multicast IPv4", "224.0.0.1"},
			{"Multicast IPv6", "ff00::1"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				allowed, err := filter.IsAllowedIP(tc.ip)
				if err != nil {
					t.Errorf("IsAllowedIP failed for %s: %v", tc.ip, err)
				}
				if allowed {
					t.Errorf("Expected IP %s to be denied even with 'allow all' rule", tc.ip)
				}
			})
		}
	})
}

func TestGetRuleAtPosition(t *testing.T) {
	jsonRules := `[
		{"action": "allow", "target": "93.184.216.0/24"},
		{"action": "deny", "target": "8.8.8.8"},
		{"action": "allow", "target": "2606:2800:220:1:248:1893:25c8:1946/64"}
	]`
	filter, err := NewIPFilter(jsonRules)
	if err != nil {
		t.Fatalf("Failed to create IPFilter: %v", err)
	}

	// Test getting rules at valid positions
	for i, expectedRule := range filter.rules {
		rule, err := filter.GetRuleAtPosition(i)
		if err != nil {
			t.Errorf("Failed to get rule at position %d: %v", i, err)
		}
		if rule.Action != expectedRule.Action || rule.Target != expectedRule.Target {
			t.Errorf("Rule mismatch at position %d: got %v, want %v", i, rule, expectedRule)
		}
	}

	// Test getting rule at invalid position
	_, err = filter.GetRuleAtPosition(-1)
	if err == nil {
		t.Error("Expected error for getting rule at position -1")
	}

	_, err = filter.GetRuleAtPosition(len(filter.rules))
	if err == nil {
		t.Error("Expected error for getting rule at position len(rules)")
	}
}

func TestUpdatePositions(t *testing.T) {
	jsonRules := `[
		{"action": "allow", "target": "93.184.216.0/24"},
		{"action": "deny", "target": "8.8.8.8"},
		{"action": "allow", "target": "2606:2800:220:1:248:1893:25c8:1946/64"}
	]`
	filter, err := NewIPFilter(jsonRules)
	if err != nil {
		t.Fatalf("Failed to create IPFilter: %v", err)
	}

	// Remove a rule from the middle
	err = filter.RemoveRuleAtPosition(1)
	if err != nil {
		t.Errorf("Failed to remove rule at position 1: %v", err)
	}

	// Verify positions are updated
	updatedRules := filter.GetAllRules()
	if len(updatedRules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(updatedRules))
	}
	if updatedRules[0].Action != "allow" || updatedRules[0].Target != "93.184.216.0/24" {
		t.Errorf("Unexpected rule at position 0: %v", updatedRules[0])
	}
	if updatedRules[1].Action != "allow" || updatedRules[1].Target != "2606:2800:220:1:248:1893:25c8:1946/64" {
		t.Errorf("Unexpected rule at position 1: %v", updatedRules[1])
	}
}

func generatePublicRulesJSON(count int, ipVersion string) string {
	rules := make([]Rule, count)
	for i := 0; i < count; i++ {
		action := "allow"
		if i%2 == 0 {
			action = "deny"
		}
		if ipVersion == "ipv4" {
			rules[i] = Rule{Action: action, Target: fmt.Sprintf("93.%d.%d.0/24", i/256, i%256)}
		} else {
			rules[i] = Rule{Action: action, Target: fmt.Sprintf("2606:2800:%x::/48", i)}
		}
	}
	jsonData, _ := json.Marshal(rules)
	return string(jsonData)
}

func benchmarkIsAllowedIPWithRules(b *testing.B, ruleCount int, ipVersion string) {
	jsonRules := generatePublicRulesJSON(ruleCount, ipVersion)
	filter, err := NewIPFilter(jsonRules)
	if err != nil {
		b.Fatal(err)
	}

	var ip string
	if ipVersion == "ipv4" {
		ip = "93.0.0.1" // This IP will match the first rule
	} else {
		ip = "2606:2800:0::1" // This IP will match the first rule
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := filter.IsAllowedIP(ip)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIsAllowedIPv410Rules(b *testing.B)    { benchmarkIsAllowedIPWithRules(b, 10, "ipv4") }
func BenchmarkIsAllowedIPv425Rules(b *testing.B)    { benchmarkIsAllowedIPWithRules(b, 25, "ipv4") }
func BenchmarkIsAllowedIPv450Rules(b *testing.B)    { benchmarkIsAllowedIPWithRules(b, 50, "ipv4") }
func BenchmarkIsAllowedIPv4100Rules(b *testing.B)   { benchmarkIsAllowedIPWithRules(b, 100, "ipv4") }
func BenchmarkIsAllowedIPv4500Rules(b *testing.B)   { benchmarkIsAllowedIPWithRules(b, 500, "ipv4") }
func BenchmarkIsAllowedIPv41000Rules(b *testing.B)  { benchmarkIsAllowedIPWithRules(b, 1000, "ipv4") }

func BenchmarkIsAllowedIPv610Rules(b *testing.B)    { benchmarkIsAllowedIPWithRules(b, 10, "ipv6") }
func BenchmarkIsAllowedIPv625Rules(b *testing.B)    { benchmarkIsAllowedIPWithRules(b, 25, "ipv6") }
func BenchmarkIsAllowedIPv650Rules(b *testing.B)    { benchmarkIsAllowedIPWithRules(b, 50, "ipv6") }
func BenchmarkIsAllowedIPv6100Rules(b *testing.B)   { benchmarkIsAllowedIPWithRules(b, 100, "ipv6") }
func BenchmarkIsAllowedIPv6500Rules(b *testing.B)   { benchmarkIsAllowedIPWithRules(b, 500, "ipv6") }
func BenchmarkIsAllowedIPv61000Rules(b *testing.B)  { benchmarkIsAllowedIPWithRules(b, 1000, "ipv6") }

func TestRuleOrderPreservation(t *testing.T) {
	// Test case for rule order preservation
	jsonRules := `[
		{"action": "allow", "target": "93.184.216.0/24"},
		{"action": "deny", "target": "8.8.8.8"},
		{"action": "allow", "target": "2606:2800:220:1:248:1893:25c8:1946/64"},
		{"action": "deny", "target": "192.168.0.0/16"},
		{"action": "allow", "target": "10.0.0.0/8"}
	]`

	filter, err := NewIPFilter(jsonRules)
	if err != nil {
		t.Fatalf("Failed to create IPFilter: %v", err)
	}

	// Verify the order of rules after loading
	rules := filter.GetAllRules()
	expectedRules := []Rule{
		{Action: "allow", Target: "93.184.216.0/24"},
		{Action: "deny", Target: "8.8.8.8"},
		{Action: "allow", Target: "2606:2800:220:1:248:1893:25c8:1946/64"},
		{Action: "deny", Target: "192.168.0.0/16"},
		{Action: "allow", Target: "10.0.0.0/8"},
	}

	if len(rules) != len(expectedRules) {
		t.Errorf("Expected %d rules, got %d", len(expectedRules), len(rules))
	}

	for i, rule := range rules {
		if rule.Action != expectedRules[i].Action || rule.Target != expectedRules[i].Target {
			t.Errorf("Rule mismatch at position %d: got %v, want %v", i, rule, expectedRules[i])
		}
	}

	// Convert back to JSON and verify the order is preserved
	outputJSON, err := filter.ToJSON()
	if err != nil {
		t.Fatalf("Failed to convert filter to JSON: %v", err)
	}

	// Create a new filter from the output JSON
	newFilter, err := NewIPFilter(outputJSON)
	if err != nil {
		t.Fatalf("Failed to create new IPFilter from output JSON: %v", err)
	}

	// Verify the order of rules in the new filter
	newRules := newFilter.GetAllRules()

	if len(newRules) != len(expectedRules) {
		t.Errorf("Expected %d rules in new filter, got %d", len(expectedRules), len(newRules))
	}

	for i, rule := range newRules {
		if rule.Action != expectedRules[i].Action || rule.Target != expectedRules[i].Target {
			t.Errorf("Rule mismatch in new filter at position %d: got %v, want %v", i, rule, expectedRules[i])
		}
	}
}