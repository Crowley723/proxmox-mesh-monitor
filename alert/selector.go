package alert

import (
	"sort"
)

func SelectAlertingNode(nodes []string) string {
	if len(nodes) == 0 {
		return ""
	}

	sort.Strings(nodes)

	return nodes[0]
}
