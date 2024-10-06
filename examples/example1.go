package main

import (
	"log"

	"github.com/mike-plivo/ipfilter"
)

func main() {
	// JSON string containing the rules
	rulesJSON := `[
		{"action": "allow", "target": "1.1.1.1"},
		{"action": "deny", "target": "1.1.1.2"},
		{"action": "allow", "target": "1.1.1.3"},
		{"action": "allow", "target": "2.2.2.0/24"},
		{"action": "allow", "target": "2001:db8::/32"},
		{"action": "deny", "target": "2001:db8:1234::/48"},
		{"action": "deny", "target": "all"}
	]`

	// Create new IPFilter
	filter, err := ipfilter.NewIPFilter(rulesJSON)
	if err != nil {
		log.Fatalf("Error creating IPFilter: %v", err)
	}

	// Example: Test IPs
	testIPs := []string{
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "2.2.2.10",
		"3.3.3.3", "2001:db8::1", "2001:db8:1234::1", "2001:db8:5678::1",
	}

	// Test IPs and print results
	for _, ip := range testIPs {
		allowed, err := filter.IsAllowedIP(ip)
		if err != nil {
			log.Printf("Error checking IP %s: %v\n", ip, err)
			continue
		}
		log.Printf("IP %s is %s\n", ip, map[bool]string{true: "allowed", false: "denied"}[allowed])
	}

	// Example: Add a new rule
	newRule := ipfilter.Rule{Action: "allow", Target: "4.4.4.4"}
	err = filter.AppendRule(newRule)
	if err != nil {
		log.Printf("Error adding new rule: %v\n", err)
	} else {
		log.Printf("Added new rule: %+v\n", newRule)
	}

	// Print the final set of rules
	finalRules := filter.GetAllRules()
	log.Printf("Final rules: %+v\n", finalRules)

	// Convert final rules to JSON
	finalJSON, err := filter.ToJSON()
	if err != nil {
		log.Printf("Error converting rules to JSON: %v\n", err)
	} else {
		log.Printf("Final rules JSON: %s\n", finalJSON)
	}
}
