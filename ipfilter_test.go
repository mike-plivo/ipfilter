package ipfilter

import (
	"os"
	"testing"
	"log"
	"github.com/stretchr/testify/assert"
)

func getRedisURL() string {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Fatalf("REDIS_URL is not set")
	}
	return redisURL
}

func cleanupRules(t *testing.T, filter *IPFilter) {
	err := filter.RemoveAllRules()
	assert.NoError(t, err, "Failed to remove all rules during cleanup")
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
			name:     "Empty rules (should deny any IP)",
			rules:    []Rule{},
			testIPs:  []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"},
			expected: []bool{false, false, false},
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
				{Action: "deny", Target: "93.184.1.0/24"},
				{Action: "allow", Target: "93.184.1.1/32"},
				{Action: "allow", Target: "2606:2800:220:1::/64"},
				{Action: "deny", Target: "2606:2800:220:1:1::/80"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"93.184.0.1", "93.184.1.0", "93.184.1.1", "192.168.1.1", "2606:2800:220:1::1", "2606:2800:220:1:1::1", "2001:4860:4860::8888"},
			expected: []bool{true, false, true, false, true, false, false},
		},
		{
			name: "Allow single IP, deny subnet containing it",
			rules: []Rule{
				{Action: "allow", Target: "192.168.1.100"},
				{Action: "deny", Target: "192.168.1.0/24"},
				{Action: "allow", Target: "all"},
			},
			testIPs:  []string{"192.168.1.100", "192.168.1.101", "192.168.2.1"},
			expected: []bool{true, false, true},
		},
		{
			name: "IPv6 specific cases",
			rules: []Rule{
				{Action: "allow", Target: "2606:2800:220:1::/64"},
				{Action: "deny", Target: "2606:2800:220:1:1::/64"},
				{Action: "allow", Target: "2606:2800:220:1:1:1::1"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"2606:2800:220:1::1", "2606:2800:220:1:1::1", "2606:2800:220:1:1:1::1", "2606:2800:220:2::1"},
			expected: []bool{true, false, true, false},
		},
		{
			name: "Mixed case sensitivity",
			rules: []Rule{
				{Action: "AlLoW", Target: "192.168.1.0/24"},
				{Action: "dEnY", Target: "ALL"},
			},
			testIPs:  []string{"192.168.1.1", "10.0.0.1"},
			expected: []bool{true, false},
		},
		{
			name: "Allow all IPv4, deny all IPv6",
			rules: []Rule{
				{Action: "allow", Target: "0.0.0.0/0"},
				{Action: "deny", Target: "::/0"},
			},
			testIPs:  []string{"192.168.1.1", "10.0.0.1", "2001:db8::1", "::1"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "Allow all IPv6, deny all IPv4",
			rules: []Rule{
				{Action: "allow", Target: "::/0"},
				{Action: "deny", Target: "0.0.0.0/0"},
			},
			testIPs:  []string{"192.168.1.1", "10.0.0.1", "2001:db8::1", "::1"},
			expected: []bool{false, false, true, true},
		},
		{
			name: "Complex IPv6 rules",
			rules: []Rule{
				{Action: "allow", Target: "2606:2800:220:1::/64"},
				{Action: "deny", Target: "2606:2800:220:1:1::/80"},
				{Action: "allow", Target: "2606:2800:220:1:1:1::/96"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"2606:2800:220:1::1", "2606:2800:220:1:1::1", "2606:2800:220:1:1:1::1", "2606:2800:220:2::1", "2001:4860:4860::8888"},
			expected: []bool{true, false, true, true, false},
		},
		{
			name: "IPv4-mapped IPv6 addresses",
			rules: []Rule{
				{Action: "allow", Target: "192.168.1.0/24"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"::ffff:192.168.1.1", "::ffff:192.168.2.1"},
			expected: []bool{true, false},
		},
		{
			name: "Localhost rules",
			rules: []Rule{
				{Action: "allow", Target: "127.0.0.1"},
				{Action: "allow", Target: "::1"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"127.0.0.1", "::1", "127.0.0.2", "::2"},
			expected: []bool{true, true, false, false},
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
			testIPs:  []string{"2606:2800:220:1:248:1893:25c8:1946", "2607:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2608::1"},
			expected: []bool{true, true, false},
		},
		{
			name: "Allow all then deny all should allow all",
			rules: []Rule{
				{Action: "allow", Target: "all"},
				{Action: "deny", Target: "all"},
			},
			testIPs:  []string{"192.168.1.1", "10.0.0.1", "2001:db8::1"},
			expected: []bool{true, true, true},
		},
		{
			name: "Deny all then allow all should deny all",
			rules: []Rule{
				{Action: "deny", Target: "all"},
				{Action: "allow", Target: "all"},
			},
			testIPs:  []string{"192.168.1.1", "10.0.0.1", "2001:db8::1"},
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