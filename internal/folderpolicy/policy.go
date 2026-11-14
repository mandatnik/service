// Package folderpolicy implements absolute folder patterns: positive rules include,
// !rules exclude, the last matching rule wins within a policy. Policies at the
// same assignment level are independent. Machine exclusions override group files.
package folderpolicy

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type Rule struct {
	Exclude bool
	Pattern string
	re      *regexp.Regexp
}
type Policy struct {
	Rules []Rule
	Roots []string
}

func Compile(text string) (*Policy, error) {
	if len(text) > 65536 || strings.ContainsRune(text, 0) {
		return nil, fmt.Errorf("текст политики слишком длинный или содержит NUL")
	}
	p := &Policy{}
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		exclude := strings.HasPrefix(line, "!")
		if exclude {
			line = strings.TrimSpace(line[1:])
		}
		line = strings.ReplaceAll(line, `\`, "/")
		if !(strings.HasPrefix(line, "/") || (len(line) > 3 && line[1] == ':' && line[2] == '/')) {
			return nil, fmt.Errorf("строка %d: нужен абсолютный путь", i+1)
		}
		if strings.Contains(line, "/../") || strings.HasSuffix(line, "/..") {
			return nil, fmt.Errorf("строка %d: переход .. запрещён", i+1)
		}
		pattern := strings.TrimRight(line, "/")
		if pattern == "" {
			pattern = "/"
		}
		expr, err := glob(pattern)
		if pattern == "/" {
			expr = ""
		}
		if err != nil {
			return nil, fmt.Errorf("строка %d: %w", i+1, err)
		}
		re, err := regexp.Compile("(?i)^" + expr + "(?:/.*)?$")
		if err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, Rule{exclude, pattern, re})
		if !exclude {
			root := pattern
			if j := strings.IndexAny(root, "*?["); j >= 0 {
				k := strings.LastIndex(root[:j], "/")
				root = root[:k+1]
			}
			unc := strings.HasPrefix(root, "//")
			root = path.Clean(root)
			if unc {
				root = "/" + root
			}
			if len(root) == 2 && root[1] == ':' {
				root += "/"
			}
			found := false
			for _, v := range p.Roots {
				if strings.EqualFold(v, root) {
					found = true
				}
			}
			if !found {
				p.Roots = append(p.Roots, root)
			}
		}
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("нужно хотя бы одно правило")
	}
	if len(p.Rules) > 256 {
		return nil, fmt.Errorf("допускается не более 256 правил")
	}
	return p, nil
}

func glob(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*':
			if i+1 < len(s) && s[i+1] == '*' {
				wholeSegment := (i == 0 || s[i-1] == '/') && (i+2 == len(s) || s[i+2] == '/')
				i++
				if !wholeSegment {
					out.WriteString("[^/]*")
					continue
				}
				if i+1 < len(s) && s[i+1] == '/' {
					i++
					out.WriteString("(?:.*/)?")
				} else {
					out.WriteString(".*")
				}
			} else {
				out.WriteString("[^/]*")
			}
		case '?':
			out.WriteString("[^/]")
		case '[':
			j := i + 1
			for j < len(s) && s[j] != ']' {
				j++
			}
			if j == len(s) {
				return "", fmt.Errorf("незакрытая группа []")
			}
			group := s[i+1 : j]
			if group == "" || strings.ContainsAny(group, "/\\") {
				return "", fmt.Errorf("некорректная группа []")
			}
			if group[0] == '!' {
				group = "^" + group[1:]
			}
			out.WriteString("[" + group + "]")
			i = j
		default:
			out.WriteString(regexp.QuoteMeta(s[i : i+1]))
		}
	}
	return out.String(), nil
}
func (p *Policy) decision(file string) (included, excluded bool) {
	file = strings.TrimRight(strings.ReplaceAll(file, `\`, "/"), "/")
	for _, r := range p.Rules {
		if r.re.MatchString(file) {
			included = !r.Exclude
			excluded = r.Exclude
		}
	}
	return
}
func (p *Policy) Includes(file string) bool { v, _ := p.decision(file); return v }
func (p *Policy) Excludes(file string) bool { _, v := p.decision(file); return v }

// MayContain prunes directories which cannot contain an included path. It
// deliberately ignores exclusions here so later re-inclusions remain possible.
func (p *Policy) MayContain(directory string) bool {
	parts := strings.Split(strings.TrimRight(strings.ReplaceAll(directory, `\`, "/"), "/"), "/")
	// If the directory is excluded, only a later positive rule can make
	// any of its descendants relevant. This avoids reading excluded subtrees.
	normalized := strings.TrimRight(strings.ReplaceAll(directory, `\`, "/"), "/")
	start := 0
	for i, rule := range p.Rules {
		if rule.re.MatchString(normalized) {
			if rule.Exclude {
				start = i + 1
			} else {
				start = 0
			}
		}
	}
	for _, rule := range p.Rules[start:] {
		if rule.Exclude {
			continue
		}
		if rule.Pattern == "/" {
			return true
		}
		pattern := strings.Split(rule.Pattern, "/")
		type state struct{ p, d int }
		memo := map[state]bool{}
		visited := map[state]bool{}
		var possible func(int, int) bool
		possible = func(pi, di int) bool {
			if pi == len(pattern) || di == len(parts) {
				return true
			}
			key := state{pi, di}
			if visited[key] {
				return memo[key]
			}
			visited[key] = true
			result := false
			if pattern[pi] == "**" {
				result = possible(pi+1, di) || possible(pi, di+1)
			} else {
				matched, _ := path.Match(strings.ReplaceAll(strings.ToLower(pattern[pi]), "[!", "[^"), strings.ToLower(parts[di]))
				result = matched && possible(pi+1, di+1)
			}
			memo[key] = result
			return result
		}
		if possible(0, 0) {
			return true
		}
	}
	return false
}
