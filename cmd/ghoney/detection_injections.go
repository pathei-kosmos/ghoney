package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Match SQL syntax across raw and collapsed comment variants
func firstSQLMatch(sources []detectionSource) (string, confidence) {
	highPatterns := [...]*regexp.Regexp{
		sqlQuotedBooleanRegex,
		sqlTruncatedQuotedBooleanRegex,
		sqlParenthesizedQuotedRegex,
		sqlCommentTailRegex,
		sqlUnionRegex,
		sqlFunctionRegex,
		sqlStructuredStackedRegex,
	}
	mediumPatterns := [...]*regexp.Regexp{
		sqlNumericBooleanRegex,
		sqlFlexibleBooleanRegex,
		sqlFlexibleHavingRegex,
		sqlHexComparisonRegex,
		sqlSleepRegex,
		sqlConditionalRegex,
		sqlHavingRegex,
		sqlStackedRegex,
	}
	var mediumSource string
	for _, source := range sources {
		for _, variant := range source.variants {
			unwrapped := sqlVersionCommentRegex.ReplaceAllString(variant, " $1 ")
			candidates := [...]string{
				variant,
				unwrapped,
				sqlBlockCommentRegex.ReplaceAllString(unwrapped, ""),
				sqlBlockCommentRegex.ReplaceAllString(unwrapped, " "),
			}
			for _, candidate := range candidates {
				if !hasSQLMarker(candidate) {
					continue
				}
				for _, pattern := range highPatterns {
					if pattern.MatchString(candidate) {
						return source.name, confidenceHigh
					}
				}
				if mediumSource == "" {
					for _, pattern := range mediumPatterns {
						if pattern.MatchString(candidate) {
							mediumSource = source.name
							break
						}
					}
				}
			}
		}
	}
	if mediumSource != "" {
		return mediumSource, confidenceMedium
	}
	return "", ""
}

// Skip expensive SQL expressions when no syntax-bearing token is present
func hasSQLMarker(value string) bool {
	for _, marker := range [...]string{
		"or", "and", "xor", "union", "select", "having", "case", "if(", "if (",
		"sleep", "benchmark", "pg_sleep", "load_file", "xp_cmdshell", "extractvalue",
		"updatexml", "waitfor", "outfile", "information_schema", "insert", "update",
		"delete", "drop", "alter", "create", "exec", "0x", "||", "&&", "--", "#", "/*",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

// Match shell signatures with a local quote splitting variant
func firstCommandMatch(sources []detectionSource) (string, confidence) {
	highPatterns := []*regexp.Regexp{
		commandAssignmentRegex,
		commandSubstitutionRegex,
		commandStrongSeparatorRegex,
		commandExplicitSeparatorRegex,
		commandEnvironmentRegex,
		commandWildcardRegex,
		commandShellStructureRegex,
	}
	mediumPatterns := []*regexp.Regexp{commandAmbiguousSeparatorRegex, commandGenericAssignmentRegex}
	if source, ok := firstDerivedRegexMatch(sources, highPatterns, normalizeShellSyntax); ok {
		return source, confidenceHigh
	}
	if source, ok := firstDerivedRegexMatch(sources, mediumPatterns, normalizeShellSyntax); ok {
		return source, confidenceMedium
	}
	return "", ""
}

// Normalize bounded shell separators and escaped command names before matching
func normalizeShellSyntax(value string) string {
	value = normalizeShellVariables(value)
	value = collapseShellEscapes(value)
	return collapseShellWordQuotes(value)
}

// Replace shell variables commonly used to hide spaces and path separators
func normalizeShellVariables(value string) string {
	var normalized strings.Builder
	normalized.Grow(len(value))
	for index := 0; index < len(value); {
		if value[index] != '$' {
			normalized.WriteByte(value[index])
			index++
			continue
		}
		remaining := value[index:]
		if strings.HasPrefix(remaining, "$ifs") {
			end := index + len("$ifs")
			if end+2 <= len(value) && value[end:end+2] == "$9" {
				end += 2
			}
			if end < len(value) && isShellWordByte(value[end]) {
				normalized.WriteByte(value[index])
				index++
				continue
			}
			normalized.WriteByte(' ')
			index = end
			continue
		}
		if strings.HasPrefix(remaining, "${ifs") {
			if end := strings.IndexByte(remaining, '}'); end >= 0 && end <= 64 {
				normalized.WriteByte(' ')
				index += end + 1
				continue
			}
		}
		if strings.HasPrefix(remaining, "${path:") {
			if end := strings.IndexByte(remaining, '}'); end >= 0 && end <= 64 {
				normalized.WriteByte('/')
				index += end + 1
				continue
			}
		}
		normalized.WriteByte(value[index])
		index++
	}
	return normalized.String()
}

// Remove backslashes that only escape bytes inside a shell word
func collapseShellEscapes(value string) string {
	var collapsed strings.Builder
	collapsed.Grow(len(value))
	changed := false
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+1 < len(value) && isShellWordByte(value[index+1]) {
			changed = true
			continue
		}
		collapsed.WriteByte(value[index])
	}
	if !changed {
		return value
	}
	return collapsed.String()
}

// Match raw and family specific variants without changing shared sources
func firstDerivedRegexMatch(sources []detectionSource, patterns []*regexp.Regexp, derive func(string) string) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			candidates := [...]string{variant, derive(variant)}
			for index, candidate := range candidates {
				if index == 1 && candidate == variant {
					continue
				}
				for _, pattern := range patterns {
					if pattern.MatchString(candidate) {
						return source.name, true
					}
				}
			}
		}
	}
	return "", false
}

// Collapse balanced quotes when they split or end a shell word
func collapseShellWordQuotes(value string) string {
	var collapsed strings.Builder
	collapsed.Grow(len(value))
	changed := false
	for index := 0; index < len(value); {
		quote := value[index]
		if (quote != '\'' && quote != '"') || index == 0 || !isShellWordByte(value[index-1]) {
			collapsed.WriteByte(value[index])
			index++
			continue
		}

		end := index + 1
		for end < len(value) && isShellWordByte(value[end]) {
			end++
		}
		if end >= len(value) || value[end] != quote {
			collapsed.WriteByte(value[index])
			index++
			continue
		}
		followedByWord := end+1 < len(value) && isShellWordByte(value[end+1])
		followedByBoundary := end+1 == len(value) || end+1 < len(value) && isShellWordBoundary(value[end+1])
		if !followedByWord && !followedByBoundary {
			collapsed.WriteByte(value[index])
			index++
			continue
		}

		collapsed.WriteString(value[index+1 : end])
		index = end + 1
		changed = true
	}
	if !changed {
		return value
	}
	return collapsed.String()
}

// Recognize delimiters after an unquoted shell command
func isShellWordBoundary(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || strings.ContainsRune(`;&|)$`+"`<>/", rune(value))
}

// Recognize bytes accepted inside the command names we track
func isShellWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_' || value == '-'
}

// Keep active browser constructs above ambiguous standalone tags and schemes
func firstXSSMatch(sources []detectionSource) (string, confidence) {
	xssSources := mergeXSSDetectionVariants(sources)
	if source, ok := firstRegexMatch(xssSources, xssActiveTagRegex, xssEventHandlerRegex, xssTagEventHandlerRegex, xssSVGAnimationHandlerRegex); ok {
		return source, confidenceHigh
	}
	if source, ok := firstRegexMatch(xssSources, xssAmbiguousTagRegex); ok {
		return source, confidenceMedium
	}
	if source, ok := firstDerivedRegexMatch(xssSources, []*regexp.Regexp{xssJavaScriptURIRegex, xssVBScriptURIRegex}, removeURLIgnoredControls); ok {
		return source, confidenceMedium
	}
	return "", ""
}

// Merge browser-only decodings without exposing them to unrelated detectors
func mergeXSSDetectionVariants(sources []detectionSource) []detectionSource {
	merged := sources
	copied := false
	for index, source := range sources {
		if len(source.xssVariants) == 0 {
			continue
		}
		if !copied {
			merged = append([]detectionSource(nil), sources...)
			copied = true
		}
		variants := make([]string, 0, len(source.variants)+len(source.xssVariants))
		variants = append(variants, source.variants...)
		variants = append(variants, source.xssVariants...)
		merged[index].variants = variants
	}
	return merged
}

// Remove only controls ignored by the URL parser
func removeURLIgnoredControls(value string) string {
	return urlIgnoredControlReplacer.Replace(value)
}

// Expand nested JNDI character tricks within a fixed budget
func firstJNDIMatch(sources []detectionSource) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			candidate := variant
			changed := false
			for pass := 0; pass < maxJNDIExpansionPasses; pass++ {
				expanded := expandInnermostJNDILookups(candidate)
				expanded = jndiCaseLookupRegex.ReplaceAllString(expanded, "$1")
				expanded = jndiDefaultLookupRegex.ReplaceAllString(expanded, "$1")
				expanded = jndiEnvironmentDefaultRegex.ReplaceAllString(expanded, "$1")
				if expanded == candidate {
					break
				}
				candidate = expanded
				changed = true
			}
			if jndiLookupRegex.MatchString(candidate) || changed && jndiExpandedLookupRegex.MatchString(candidate) {
				return source.name, true
			}
		}
	}
	return "", false
}

// Resolve innermost lookup fragments that can contribute characters to JNDI
func expandInnermostJNDILookups(value string) string {
	var expanded strings.Builder
	expanded.Grow(len(value))
	changed := false
	for cursor := 0; cursor < len(value); {
		endRelative := strings.IndexByte(value[cursor:], '}')
		if endRelative < 0 {
			expanded.WriteString(value[cursor:])
			break
		}
		end := cursor + endRelative
		startRelative := strings.LastIndex(value[cursor:end], "${")
		if startRelative < 0 {
			expanded.WriteString(value[cursor : end+1])
			cursor = end + 1
			continue
		}
		start := cursor + startRelative
		expanded.WriteString(value[cursor:start])
		body := value[start+2 : end]
		replacement, ok := jndiLookupFragment(body)
		if !ok {
			expanded.WriteString(value[start : end+1])
		} else {
			expanded.WriteString(replacement)
			changed = true
		}
		cursor = end + 1
	}
	if !changed {
		return value
	}
	return expanded.String()
}

// Interpret only short lookup forms used to construct a JNDI prefix
func jndiLookupFragment(body string) (string, bool) {
	body = strings.TrimSpace(body)
	if body == "" || len(body) > 192 {
		return "", false
	}
	if body == "j" || body == "n" || body == "d" || body == "i" || body == "jn" || body == "di" || body == "jndi" {
		return body, true
	}
	prefix, argument, found := strings.Cut(body, ":")
	if !found {
		return "", false
	}
	prefix = strings.TrimSpace(prefix)
	argument = strings.TrimSpace(argument)
	if strings.EqualFold(prefix, "lower") {
		return strings.ToLower(argument), argument != ""
	}
	if strings.EqualFold(prefix, "upper") {
		return strings.ToUpper(argument), argument != ""
	}
	if _, fallback, found := strings.Cut(argument, ":-"); found {
		return strings.TrimSpace(fallback), true
	}
	if strings.HasPrefix(argument, "-") {
		return strings.TrimSpace(strings.TrimPrefix(argument, "-")), true
	}
	switch strings.ToLower(prefix) {
	case "sys", "date", "main", "ctx", "env":
		return argument, argument != ""
	default:
		return "", false
	}
}

// Match explicit NoSQL keys in JSON objects, query strings and form bodies
func firstNoSQLMatch(input detectionInput) (string, confidence) {
	bestSource := ""
	best := confidence("")
	keepStrongest := func(source string, value confidence) bool {
		if confidenceRank(value) > confidenceRank(best) {
			bestSource = source
			best = value
		}
		return best == confidenceHigh
	}

	if keepStrongest("request body", noSQLJSONConfidence(input.Body)) {
		return bestSource, best
	}
	for _, candidate := range normalizeDetectionVariants(input.RawQuery, true) {
		if keepStrongest("query string", noSQLParameterConfidence(candidate)) {
			return bestSource, best
		}
	}
	if isFormContentType(input.Header.Get("Content-Type")) {
		for _, candidate := range normalizeDetectionVariants(input.Body, true) {
			if keepStrongest("request body", noSQLParameterConfidence(candidate)) {
				return bestSource, best
			}
		}
	}
	if isMultipartContentType(input.Header.Get("Content-Type")) {
		if fields, ok := parseMultipartTextFields(input.Body, input.Header.Get("Content-Type")); ok {
			for _, field := range fields {
				if keepStrongest("request body", noSQLKeyConfidence(field.key)) {
					return bestSource, best
				}
			}
		}
	}
	return bestSource, best
}

// Read NoSQL operators from JSON keys rather than values
func noSQLJSONConfidence(body string) confidence {
	if body == "" || len(body) > maxRequestBodySize || !json.Valid([]byte(body)) {
		return ""
	}
	var value any
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		return ""
	}
	return noSQLValueConfidence(value)
}

// Find the strongest NoSQL operator in a JSON tree
func noSQLValueConfidence(value any) confidence {
	best := confidence("")
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			best = maxConfidence(best, noSQLKeyConfidence(key))
			best = maxConfidence(best, noSQLValueConfidence(child))
			if best == confidenceHigh {
				return best
			}
		}
	case []any:
		for _, child := range typed {
			best = maxConfidence(best, noSQLValueConfidence(child))
			if best == confidenceHigh {
				return best
			}
		}
	}
	return best
}

// Require dotted or bracket notation in query and form keys
func noSQLParameterConfidence(value string) confidence {
	best := confidence("")
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == ';' }) {
		key, _, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found || (!strings.Contains(key, ".") && !(strings.Contains(key, "[") && strings.Contains(key, "]"))) {
			continue
		}
		best = maxConfidence(best, noSQLKeyConfidence(key))
		if best == confidenceHigh {
			return best
		}
	}
	return best
}

// Read exact dotted and bracket NoSQL key parts
func noSQLKeyConfidence(key string) confidence {
	key = strings.ToLower(strings.Trim(strings.TrimSpace(key), `"'`))
	components := strings.FieldsFunc(key, func(r rune) bool { return r == '.' || r == '[' || r == ']' })
	for _, component := range components {
		switch component {
		case "$where", "$function", "$accumulator":
			return confidenceHigh
		case "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex", "$exists",
			"$or", "$and", "$nor", "$not", "$expr", "$mod", "$size", "$all", "$elemmatch", "$type",
			"$jsonschema", "$text", "$near", "$nearsphere", "$geowithin", "$geointersects",
			"$bit", "$bitand", "$bitor", "$bitsallclear", "$bitsallset", "$bitsanyclear", "$bitsanyset":
			return confidenceMedium
		}
	}
	return ""
}

// Keep the strongest confidence found for a family
func maxConfidence(left, right confidence) confidence {
	if confidenceRank(right) > confidenceRank(left) {
		return right
	}
	return left
}
