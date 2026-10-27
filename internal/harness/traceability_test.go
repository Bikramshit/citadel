package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// requiredIDs lists every rule ID, test ID, and invariant in the
// specification.
func requiredIDs() (rules, tests, invariants []string) {
	rules = []string{"A0", "A1", "A2", "A3", "A4", "A5", "I1", "I2", "I3", "F0", "F1", "F3", "E1", "E2",
		"H1", "H2", "H3", "H4", "H5", "H6", "C1", "D0"}
	for i := 1; i <= 7; i++ {
		tests = append(tests, fmt.Sprintf("T-A%d", i), fmt.Sprintf("L%d", i), fmt.Sprintf("CT%d", i))
	}
	for i := 1; i <= 5; i++ {
		tests = append(tests, fmt.Sprintf("D%d", i))
	}
	for i := 1; i <= 13; i++ {
		tests = append(tests, fmt.Sprintf("E-T%d", i))
		invariants = append(invariants, fmt.Sprint(i))
	}
	for i := 1; i <= 18; i++ {
		tests = append(tests, fmt.Sprintf("P%d", i))
	}
	tests = append(tests, "X1", "X2", "X3", "M1")
	return rules, tests, invariants
}

var testName = regexp.MustCompile("`((?:Test|Fuzz|Benchmark)[A-Za-z0-9_]+)`")

// TestTraceability parses docs/TRACEABILITY.md and fails if any
// specification ID has no test, any rule lacks a positive or a negative
// test, or any listed test function does not exist.
func TestTraceability(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "docs/TRACEABILITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]bool{}
	decl := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark)[A-Za-z0-9_]+)\(`)
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			defined[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]map[string][]string{} // section -> id -> cells
	section := ""
	for _, line := range strings.Split(string(doc), "\n") {
		if h, ok := strings.CutPrefix(line, "## "); ok {
			section = h
			sections[section] = map[string][]string{}
			continue
		}
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		id := strings.Trim(cells[0], "` ")
		if section != "" {
			sections[section][id] = cells[1:]
		}
		for _, m := range testName.FindAllStringSubmatch(line, -1) {
			if !defined[m[1]] {
				t.Errorf("TRACEABILITY.md lists %s, which does not exist", m[1])
			}
		}
	}
	rules, tests, invariants := requiredIDs()
	for _, r := range rules {
		cells, ok := sections["Rules"][r]
		switch {
		case !ok:
			t.Errorf("rule %s is not traced", r)
		case len(cells) < 2:
			t.Errorf("rule %s row is malformed", r)
		case len(testName.FindAllString(cells[1], -1)) == 0:
			t.Errorf("rule %s has no negative test", r)
		case len(testName.FindAllString(cells[0], -1)) == 0 && cells[0] != "not applicable":
			t.Errorf("rule %s has no positive test", r)
		}
	}
	for _, id := range tests {
		cells, ok := sections["Tests"][id]
		if !ok || len(testName.FindAllString(strings.Join(cells, " "), -1)) == 0 {
			t.Errorf("test ID %s has no test", id)
		}
	}
	for _, n := range invariants {
		cells, ok := sections["Invariants"][n]
		if !ok || len(testName.FindAllString(strings.Join(cells, " "), -1)) == 0 {
			t.Errorf("invariant %s has no test", n)
		}
	}
}
