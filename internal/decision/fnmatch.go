package decision

import (
	"regexp"
	"strings"
	"sync"
)

// Python's fnmatch, not Go's path.Match.
//
// The obvious implementation is path.Match from the standard library, and it is
// wrong here in a way that would not show up until it mattered. Go's `*` stops
// at a `/`, so the pattern `a*` does not match `a/b`; Python's `*` crosses it
// happily. The policies this enforces are authored against Python semantics, so
// a tool named `svc/delete` would slip past a rule meant to catch `svc*` — a
// silent narrowing of a security rule, which is the worst direction for one to
// move in.
//
// Go's path.Match also rejects a malformed pattern with an error, where Python
// treats an unterminated `[` as a literal bracket. Neither behaviour is more
// correct; they simply differ, and the whole point of this package is that the
// two runtimes do not differ.
//
// So this translates the pattern the way CPython's fnmatch.translate does and
// hands the result to regexp. The conformance fixtures carry cases that separate
// the two implementations, so a regression here fails the build rather than
// quietly changing what a policy means.

var (
	cacheMu sync.RWMutex
	cache   = map[string]*regexp.Regexp{}
)

// translate converts a glob to a Go regexp source string, following CPython's
// fnmatch.translate. The `(?s)` flag makes `.` match newlines, as Python's
// translation does.
func translate(pat string) string {
	var out strings.Builder
	out.WriteString("(?s)\\A")

	r := []rune(pat)
	n := len(r)
	i := 0
	for i < n {
		c := r[i]
		i++
		switch c {
		case '*':
			out.WriteString(".*")
		case '?':
			out.WriteString(".")
		case '[':
			j := i
			if j < n && r[j] == '!' {
				j++
			}
			if j < n && r[j] == ']' {
				j++
			}
			for j < n && r[j] != ']' {
				j++
			}
			if j >= n {
				// Unterminated class. Python emits a literal '['.
				out.WriteString("\\[")
			} else {
				stuff := string(r[i:j])
				// Python escapes backslashes inside the class, then rewrites a
				// leading '!' to '^' and escapes a leading '^' or '['.
				stuff = strings.ReplaceAll(stuff, "\\", "\\\\")
				if strings.HasPrefix(stuff, "!") {
					stuff = "^" + stuff[1:]
				} else if strings.HasPrefix(stuff, "^") || strings.HasPrefix(stuff, "[") {
					stuff = "\\" + stuff
				}
				out.WriteString("[" + stuff + "]")
				i = j + 1
			}
		default:
			out.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	out.WriteString("\\z")
	return out.String()
}

// FnMatch reports whether name matches pattern, case-sensitively, using
// Python's fnmatch.fnmatchcase semantics.
//
// A pattern that will not compile is treated as matching nothing. Returning
// false is the safe direction: a broken pattern in an allow rule stops allowing,
// where returning true would start permitting whatever the author fat-fingered.
func FnMatch(name, pattern string) bool {
	cacheMu.RLock()
	re, ok := cache[pattern]
	cacheMu.RUnlock()
	if !ok {
		compiled, err := regexp.Compile(translate(pattern))
		if err != nil {
			compiled = nil
		}
		cacheMu.Lock()
		cache[pattern] = compiled
		cacheMu.Unlock()
		re = compiled
	}
	if re == nil {
		return false
	}
	return re.MatchString(name)
}

// matchAny reports whether name matches any of the patterns.
func matchAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if FnMatch(name, p) {
			return true
		}
	}
	return false
}
