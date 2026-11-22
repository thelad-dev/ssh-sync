package releaseverify

import (
	"fmt"
	"strconv"
	"strings"
)

// CompareVersions returns -1 if a<b, 0 if equal, 1 if a>b.
// Accepts dotted numeric versions (semver-like without pre-release), e.g. "1.2.3".
// Suffix after '-' is ignored for ordering (1.0.0-dev < 1.0.0 only if we strip; here
// "1.0.0-dev" compares as 1.0.0 against numeric core, then pre-release loses to release).
func CompareVersions(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, fmt.Errorf("version %q: %w", a, err)
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, fmt.Errorf("version %q: %w", b, err)
	}
	n := len(pa.nums)
	if len(pb.nums) > n {
		n = len(pb.nums)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(pa.nums) {
			ai = pa.nums[i]
		}
		if i < len(pb.nums) {
			bi = pb.nums[i]
		}
		if ai < bi {
			return -1, nil
		}
		if ai > bi {
			return 1, nil
		}
	}
	// No pre-release beats pre-release.
	if pa.pre == "" && pb.pre != "" {
		return 1, nil
	}
	if pa.pre != "" && pb.pre == "" {
		return -1, nil
	}
	if pa.pre < pb.pre {
		return -1, nil
	}
	if pa.pre > pb.pre {
		return 1, nil
	}
	return 0, nil
}

type parsedVersion struct {
	nums []int
	pre  string
}

func parseVersion(s string) (parsedVersion, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return parsedVersion{}, fmt.Errorf("leer")
	}
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 {
		return parsedVersion{}, fmt.Errorf("ungültig")
	}
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return parsedVersion{}, fmt.Errorf("ungültig")
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return parsedVersion{}, fmt.Errorf("ungültig")
		}
		nums = append(nums, n)
	}
	return parsedVersion{nums: nums, pre: pre}, nil
}
