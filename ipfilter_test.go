package ipfilter

import (
	"fmt"
	"os"
	"testing"
	"github.com/stretchr/testify/assert"
)

type testingT interface {
	Error(args ...interface{})
}

func getRedisURL() string {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}
	return redisURL
}

func cleanupRules(t testingT, filter *IPFilter) {
	err := filter.RemoveAllRules()
	if err != nil {
		t.Error("Failed to remove all rules during cleanup:", err)
	}
}

func TestIPFilter(t *testing.T) {
	filter := NewIPFilter(getRedisURL())
	defer cleanupRules(t, filter)

	// Ensure rules are cleared at the start
	cleanupRules(t, filter)

	// Test adding rules
	rule1 := Rule{Action: "allow", Target: "93.184.216.0/24"}
	rule2 := Rule{Action: "deny", Target: "8.8.8.8"}
	
	_, err := filter.AppendRule(rule1)
	assert.NoError(t, err)
	
	_, err = filter.AppendRule(rule2)
	assert.NoError(t, err)

	// Test getting all rules
	rules, err := filter.GetAllRules()
	assert.NoError(t, err)
	assert.Len(t, rules, 2)
	assert.Equal(t, rule1.Action, rules[0].Action)
	assert.Equal(t, rule1.Target, rules[0].Target)
	assert.Equal(t, rule2.Action, rules[1].Action)
	assert.Equal(t, rule2.Target, rules[1].Target)

	// Test IsAllowedIP
	allowed, err := filter.IsAllowedIP("93.184.216.34")
	assert.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = filter.IsAllowedIP("8.8.8.8")
	assert.NoError(t, err)
	assert.False(t, allowed)

	// Test adding a rule at a specific position
	rule3 := Rule{Action: "allow", Target: "2606:2800:220:1:248:1893:25c8:1946/64"}
	err = filter.AddRuleAtPosition(rule3, 1)
	assert.NoError(t, err)

	// Verify the new rule was added at the correct position
	ruleAtPos, err := filter.GetRuleAtPosition(1)
	assert.NoError(t, err)
	assert.Equal(t, rule3.Action, ruleAtPos.Action)
	assert.Equal(t, rule3.Target, ruleAtPos.Target)

	// Test removing a rule at a specific position
	err = filter.RemoveRuleAtPosition(0)
	assert.NoError(t, err)

	// Verify the rule was removed
	ruleCount, err := filter.GetRuleCount()
	assert.NoError(t, err)
	assert.Equal(t, int64(2), ruleCount)

	// Test removing all rules
	err = filter.RemoveAllRules()
	assert.NoError(t, err)

	// Verify all rules were removed
	ruleCount, err = filter.GetRuleCount()
	assert.NoError(t, err)
	assert.Equal(t, int64(0), ruleCount)

	// Test custom ruleKey
	customRuleKey := "custom_ip_rules"
	customFilter := NewIPFilter(getRedisURL(), customRuleKey)
	assert.Equal(t, customRuleKey, customFilter.GetRuleKey(), "Custom rule key not set correctly")

	// Test default ruleKey
	defaultFilter := NewIPFilter(getRedisURL())
	assert.Equal(t, "ip_rules", defaultFilter.GetRuleKey(), "Default rule key not set correctly")
}

func TestValidateRule(t *testing.T) {
	validRules := []Rule{
		{Action: "allow", Target: "93.184.216.0/24"},
		{Action: "deny", Target: "8.8.8.8"},
		{Action: "allow", Target: "all"},
	}

	for _, rule := range validRules {
		err := ValidateRule(rule)
		assert.NoError(t, err)
	}

	invalidRules := []Rule{
		{Action: "invalid", Target: "93.184.216.0/24"},
		{Action: "allow", Target: ""},
		{Action: "", Target: "8.8.8.8"},
	}

	for _, rule := range invalidRules {
		err := ValidateRule(rule)
		assert.Error(t, err)
	}
}

func TestGetRuleAtPosition(t *testing.T) {
	filter := NewIPFilter(getRedisURL())
	defer cleanupRules(t, filter)

	// Ensure rules are cleared at the start
	cleanupRules(t, filter)

	var err error

	// Add some rules
	rules := []Rule{
		{Action: "allow", Target: "93.184.216.0/24"},
		{Action: "deny", Target: "8.8.8.8"},
		{Action: "allow", Target: "2606:2800:220:1:248:1893:25c8:1946/64"},
	}

	for _, rule := range rules {
		_, err := filter.AppendRule(rule)
		assert.NoError(t, err)
	}

	// Test getting rules at valid positions
	for i, expectedRule := range rules {
		rule, err := filter.GetRuleAtPosition(i)
		assert.NoError(t, err)
		assert.Equal(t, expectedRule.Action, rule.Action)
		assert.Equal(t, expectedRule.Target, rule.Target)
		assert.Equal(t, i, rule.Position)
	}

	// Test getting rule at invalid position
	_, err = filter.GetRuleAtPosition(-1)
	assert.Error(t, err)

	_, err = filter.GetRuleAtPosition(len(rules))
	assert.Error(t, err)
}

func TestUpdatePositions(t *testing.T) {
	filter := NewIPFilter(getRedisURL())
	defer cleanupRules(t, filter)

	// Ensure rules are cleared at the start
	cleanupRules(t, filter)

	var err error
	// Add some rules
	rules := []Rule{
		{Action: "allow", Target: "93.184.216.0/24"},
		{Action: "deny", Target: "8.8.8.8"},
		{Action: "allow", Target: "2606:2800:220:1:248:1893:25c8:1946/64"},
	}

	for _, rule := range rules {
		_, err := filter.AppendRule(rule)
		assert.NoError(t, err)
	}

	// Remove a rule from the middle
	err = filter.RemoveRuleAtPosition(1)
	assert.NoError(t, err)

	// Verify positions are updated
	updatedRules, err := filter.GetAllRules()
	assert.NoError(t, err)
	assert.Len(t, updatedRules, 2)
	assert.Equal(t, 0, updatedRules[0].Position)
	assert.Equal(t, 1, updatedRules[1].Position)
}

func TestExtendedIPFilter(t *testing.T) {
	filter := NewIPFilter(getRedisURL())
	defer cleanupRules(t, filter)

	testCases := []struct {
		name     string
		rules    []Rule
		testIPs  []string
		expected []bool
	}{
		{
			name:     "Empty rules (should allow any IP)",
			rules:    []Rule{},
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"},
			expected: []bool{true, true, true},
		},
		{
			name: "Allow all",
			rules: []Rule{
				{Action: "allow", Target: "all"},
			},
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"},
			expected: []bool{true, true, true},
		},
		{
			name: "Deny all",
			rules: []Rule{
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"},
			expected: []bool{false, false, false},
		},
		{
			name: "Allow specific IPv4",
			rules: []Rule{
				{Action: "allow", Target: "93.184.216.34"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"93.184.216.34", "93.184.216.35", "8.8.8.8"},
			expected: []bool{true, false, false},
		},
		{
			name: "Allow IPv4 range",
			rules: []Rule{
				{Action: "allow", Target: "93.184.216.0/24"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"93.184.216.34", "93.184.216.254", "8.8.8.8"},
			expected: []bool{true, true, false},
		},
		{
			name: "Allow specific IPv6",
			rules: []Rule{
				{Action: "allow", Target: "2606:2800:220:1:248:1893:25c8:1946"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1:248:1893:25c8:1947", "2001:4860:4860::8888"},
			expected: []bool{true, false, false},
		},
		{
			name: "Allow IPv6 range",
			rules: []Rule{
				{Action: "allow", Target: "2606:2800:220:1::/64"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1::1", "2001:4860:4860::8888"},
			expected: []bool{true, true, false},
		},
		{
			name: "Mixed IPv4 and IPv6 rules",
			rules: []Rule{
				{Action: "allow", Target: "93.184.216.0/24"},
				{Action: "allow", Target: "2606:2800:220:1::/64"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "8.8.8.8", "2001:4860:4860::8888"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "Overlapping rules (first match wins)",
			rules: []Rule{
				{Action: "deny", Target: "93.184.216.0/24"},
				{Action: "allow", Target: "93.184.216.34"},
				{Action: "allow", Target: "all"},
			},
			testIPs:  []string{"93.184.216.33", "93.184.216.34", "8.8.8.8"},
			expected: []bool{false, false, true},
		},
		{
			name: "Complex rule set",
			rules: []Rule{
				{Action: "allow", Target: "93.184.0.0/16"},
				{Action: "deny", Target: "200.200.200.0/24"},
				{Action: "allow", Target: "99.184.1.1/32"},
				{Action: "deny", Target: "99.184.1.0/24"},
				{Action: "allow", Target: "2606:2800:220:1::/64"},
				{Action: "deny", Target: "2606:2800:220:1:1::/80"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"93.184.0.1", "200.200.200.200", "99.184.1.1", "99.184.1.2", "2606:2800:220:1::1", "2505:2800:220:1:1::1", "2001:4860:4860::8888"},
			expected: []bool{true, false, true, false, true, false, false},
		},
		{
			name: "Allow single IP, deny subnet containing it",
			rules: []Rule{
				{Action: "allow", Target: "199.10.1.100"},
				{Action: "deny", Target: "199.10.1.0/24"},
				{Action: "allow", Target: "all"},
			},
			testIPs:  []string{"199.10.1.100", "199.10.1.101", "199.10.2.1", "200.200.200.200"},
			expected: []bool{true, false, true, true},
		},
		{
			name: "IPv6 specific cases",
			rules: []Rule{
				{Action: "allow", Target: "2606:2800:220:1::/64"},
				{Action: "deny", Target: "2606:2800:220:1:1::/64"},
				{Action: "allow", Target: "2606:2800:220:1:1:1::1"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"2606:2800:220:1::1", "2506:2800:220:1:1::1", "2606:2800:220:1:1:1::1", "2606:2800:220:2::1"},
			expected: []bool{true, false, true, false},
		},
		{
			name: "Allow all IPv4, deny all IPv6",
			rules: []Rule{
				{Action: "allow", Target: "0.0.0.0/0"},
				{Action: "deny", Target: "::/0"},
			},
			testIPs:  []string{"213.0.113.1", "190.51.100.1", "2006:db8::1", "2606:2800:220:1:1:1::1"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "Allow all IPv6, deny all IPv4",
			rules: []Rule{
				{Action: "allow", Target: "::/0"},
				{Action: "deny", Target: "0.0.0.0/0"},
			},
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888"},
			expected: []bool{false, false, true, true},
		},
		{
			name: "Complex IPv6 rules",
			rules: []Rule{
				{Action: "allow", Target: "2606:2800:220::/64"},
				{Action: "deny", Target: "2606:2800:220:1::/80"},
				{Action: "allow", Target: "2606:2800:220:1:1::/96"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"2606:2800:220:0:1:2:3:4", "2606:2800:220:1:5:6:7:8", "2606:2800:220:0:1:9:10:11", "2606:2800:220:2::1", "2505:4860:4860::8888"},
			expected: []bool{true, false, true, false, false},
		},
		{
			name: "Localhost is always denied",
			rules: []Rule{
				{Action: "allow", Target: "all"},
			},
			testIPs:  []string{"127.0.0.1", "::1"},
			expected: []bool{false, false},
		},
		{
			name: "Large IPv4 range",
			rules: []Rule{
				{Action: "allow", Target: "93.184.0.0/16"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"93.184.0.1", "93.184.255.255", "93.185.0.1"},
			expected: []bool{true, true, false},
		},
		{
			name: "Large IPv6 range",
			rules: []Rule{
				{Action: "allow", Target: "2606:2800::/24"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"2606:2800:220:1:248:1893:25c8:1946", "2606:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2608::1"},
			expected: []bool{true, false, false},
		},
		{
			name: "Allow all then deny all, should allow all",
			rules: []Rule{
				{Action: "allow", Target: "all"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"83.0.113.1", "98.51.100.1", "2006:db8::1"},
			expected: []bool{true, true, true},
		},
		{
			name: "Deny all then allow all should deny all",
			rules: []Rule{
				{Action: "deny", Target: "all"},
				{Action: "allow", Target: "all"},
			},
			testIPs:  []string{"83.0.113.1", "98.51.100.1", "2006:db8::1"},
			expected: []bool{false, false, false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Ensure rules are cleared at the start of each subtest
			cleanupRules(t, filter)

			// Add new rules
			for _, rule := range tc.rules {
				_, err := filter.AppendRule(rule)
				assert.NoError(t, err)
			}

			// Test each IP
			for i, ip := range tc.testIPs {
				allowed, err := filter.IsAllowedIP(ip)
				assert.NoError(t, err)
				assert.Equal(t, tc.expected[i], allowed, "Unexpected result for IP %s", ip)
			}
		})
	}

	// Updated test case for private and special IP blocks
	t.Run("Private and special IP blocks", func(t *testing.T) {
		// Ensure rules are cleared at the start
		cleanupRules(t, filter)

		// Add a rule to allow all
		_, err := filter.AppendRule(Rule{Action: "allow", Target: "all"})
		assert.NoError(t, err)

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
				assert.NoError(t, err)
				assert.False(t, allowed, "Expected IP %s to be denied even with 'allow all' rule", tc.ip)
			})
		}
	})
}

func generatePublicRulesIPv4(count int) []Rule {
	rules := make([]Rule, count)
	for i := 0; i < count; i++ {
		action := "allow"
		if i%2 == 0 {
			action = "deny"
		}
		rules[i] = Rule{Action: action, Target: fmt.Sprintf("93.%d.%d.0/24", i/256, i%256)}
	}
	return rules
}

func generatePublicRulesIPv6(count int) []Rule {
	rules := make([]Rule, count)
	for i := 0; i < count; i++ {
		action := "allow"
		if i%2 == 0 {
			action = "deny"
		}
		// Using 2606:2800::/32, which is assigned to Akamai Technologies
		rules[i] = Rule{Action: action, Target: fmt.Sprintf("2606:2800:%x::/48", i)}
	}
	return rules
}

func benchmarkIsAllowedIPWithRules(b *testing.B, ruleCount int, ipVersion string) {
	filter := NewIPFilter(getRedisURL())
	defer cleanupRules(b, filter)

	var rules []Rule
	var ip string

	if ipVersion == "ipv4" {
		rules = generatePublicRulesIPv4(ruleCount)
		ip = "93.0.0.1" // This IP will match the first rule
	} else {
		rules = generatePublicRulesIPv6(ruleCount)
		ip = "2606:2800:0::1" // This IP will match the first rule
	}

	for _, rule := range rules {
		_, err := filter.AppendRule(rule)
		if err != nil {
			b.Fatal(err)
		}
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