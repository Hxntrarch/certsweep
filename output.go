package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type Result struct {
	Domain   string `json:"domain"`
	SourceIP string `json:"source_ip"`
	Org      string `json:"org,omitempty"`
	Match    string `json:"match"`
}

func writeResults(results []Result, cfg *Config) error {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Domain < results[j].Domain
	})

	f, err := os.Create(cfg.OutputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, r := range results {
		var line string
		if cfg.JSONOutput {
			b, _ := json.Marshal(r)
			line = string(b)
		} else {
			line = r.Domain
		}
		fmt.Fprintln(f, line)
		if !cfg.Silent {
			fmt.Println(line)
		}
	}
	return nil
}
