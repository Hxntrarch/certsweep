package main

import (
	"fmt"
	"net"
)

// splitTo24 takes a list of CIDR strings (any size) and splits
// anything larger than /24 into individual /24 blocks. Deduplicates.
func splitTo24(cidrs []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, cidrStr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// If it's not a valid CIDR, pass it through as-is
			if !seen[cidrStr] {
				seen[cidrStr] = true
				result = append(result, cidrStr)
			}
			continue
		}

		ones, bits := ipnet.Mask.Size()

		// IPv6 or already /24 or smaller — keep as-is
		if bits != 32 || ones >= 24 {
			key := ipnet.String()
			if !seen[key] {
				seen[key] = true
				result = append(result, key)
			}
			continue
		}

		// Split into /24 blocks
		ip := ipnet.IP.To4()
		if ip == nil {
			continue
		}

		count := 1 << (24 - ones)
		for i := 0; i < count; i++ {
			block := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
			if !seen[block] {
				seen[block] = true
				result = append(result, block)
			}

			// Increment the third octet
			ip[2]++
			if ip[2] == 0 {
				ip[1]++
				if ip[1] == 0 {
					ip[0]++
				}
			}
		}
	}

	return result
}
