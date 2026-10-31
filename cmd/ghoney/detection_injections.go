package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Match SQL syntax across raw and collapsed comment variants
func firstSQLMatch(sources []detectionSource) (detectionMatch, confidence) {
	highPatterns := [...]*regexp.Regexp{
		sqlQuotedBooleanRegex,
		sqlTruncatedQuotedBooleanRegex,
		sqlParenthesizedQuotedRegex,
		sqlUnionRegex,
		sqlFunctionRegex,
		sqlStructuredStackedRegex,
	}
	mediumPatterns := [...]*regexp.Regexp{
		sqlNumericBooleanRegex,
		sqlFlexibleBooleanRegex,
		sqlFlexibleHavingRegex,
		sqlHexComparisonRegex,
		sqlBareBooleanRegex,
		sqlPredicateRegex,
		sqlFunctionComparisonRegex,
		sqlReconnaissanceRegex,
		sqlBooleanExpressionRegex,
		sqlSleepRegex,
		sqlConditionalRegex,
		sqlHavingRegex,
		sqlStackedRegex,
		sqlCommentTailRegex,
	}
	var mediumSource detectionMatch
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			if !hasSQLMarker(variant) {
				continue
			}
			candidates := []string{variant}
			if strings.Contains(variant, "/*") {
				unwrapped := sqlVersionCommentRegex.ReplaceAllString(variant, " $1 ")
				candidates = append(candidates, unwrapped, sqlBlockCommentRegex.ReplaceAllString(unwrapped, ""), sqlBlockCommentRegex.ReplaceAllString(unwrapped, " "))
			}
			seenCandidates := make(map[string]struct{}, len(candidates))
			for _, candidate := range candidates {
				if _, exists := seenCandidates[candidate]; exists {
					continue
				}
				seenCandidates[candidate] = struct{}{}
				if !hasSQLMarker(candidate) {
					continue
				}
				for _, pattern := range highPatterns {
					if (pattern == sqlQuotedBooleanRegex || pattern == sqlTruncatedQuotedBooleanRegex || pattern == sqlParenthesizedQuotedRegex) && !strings.ContainsAny(candidate, "'\"`)") {
						continue
					}
					if pattern == sqlUnionRegex && !strings.Contains(candidate, "union") {
						continue
					}
					if pattern == sqlStructuredStackedRegex && !strings.Contains(candidate, ";") {
						continue
					}
					if location := pattern.FindStringIndex(candidate); location != nil {
						return evidenceMatch(source.name, candidate, location[0]), confidenceHigh
					}
				}
				if mediumSource.source == "" {
					for _, pattern := range mediumPatterns {
						if location := pattern.FindStringIndex(candidate); location != nil {
							mediumSource = evidenceMatch(source.name, candidate, location[0])
							break
						}
					}
				}
			}
		}
	}
	if mediumSource.source != "" {
		return mediumSource, confidenceMedium
	}
	return detectionMatch{}, ""
}

// Skip SQL matching when no SQL markers are present
func hasSQLMarker(value string) bool {
	// Every supported SQL shape needs an operand, delimiter or standalone construct
	if !strings.ContainsAny(value, "0123456789'\"`();#") && !strings.Contains(value, "/*") &&
		!strings.Contains(value, "union") && !strings.Contains(value, "true") && !strings.Contains(value, "false") &&
		!strings.Contains(value, "waitfor") && !strings.Contains(value, "outfile") && !strings.Contains(value, "information_schema") {
		return false
	}
	for _, marker := range [...]string{
		"order", "group", "limit", "offset", "procedure", "for update", "or", "and", "xor", "union", "select", "having", "between", " in ", " is ", "exists", "case", "if(", "if (",
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
func firstCommandMatch(sources []detectionSource) (detectionMatch, confidence) {
	sources = sourcesWithMarker(sources, hasCommandMarker)
	highPatterns := []*regexp.Regexp{
		commandBase64SeparatorRegex,
		commandShellVariableRegex,
		commandAssignmentRegex,
		commandSubstitutionRegex,
		commandStrongSeparatorRegex,
		commandExplicitSeparatorRegex,
		commandEnvironmentRegex,
		commandWildcardRegex,
		commandShellStructureRegex,
	}
	mediumPatterns := []*regexp.Regexp{commandAmbiguousSeparatorRegex, commandExecutablePathRegex, commandGenericAssignmentRegex}
	if source, ok := firstDerivedRegexMatch(sources, highPatterns, normalizeShellSyntax); ok {
		return source, confidenceHigh
	}
	if source, ok := firstDerivedRegexMatch(sources, mediumPatterns, normalizeShellSyntax); ok {
		return source, confidenceMedium
	}
	return detectionMatch{}, ""
}

// Skip plain prose and numeric assignments without excluding shell separators
func hasCommandMarker(value string) bool {
	if strings.ContainsAny(value, ";|\r\n$`\\") || strings.Contains(value, "&&") {
		return true
	}
	for index := 0; index < len(value); index++ {
		if value[index] != '=' && value[index] != ':' && value[index] != '&' {
			continue
		}
		candidate := strings.TrimLeft(value[index+1:], " \t\"'({")
		if candidate == "" {
			continue
		}
		if value[index] == '&' {
			end := 0
			for end < len(candidate) && isShellWordByte(candidate[end]) {
				end++
			}
			if end < len(candidate) && candidate[end] == '=' {
				continue
			}
		}
		if candidate[0] >= 'a' && candidate[0] <= 'z' || candidate[0] == '/' || candidate[0] == '_' {
			return true
		}
	}
	return false
}

// Normalize bounded shell separators and escaped command names before matching
func normalizeShellSyntax(value string) string {
	value = shellEmptyExpansionRegex.ReplaceAllString(value, "$1$2")
	value = shellDefaultExpansionRegex.ReplaceAllString(value, "$1")
	value = normalizeShellVariables(value)
	value = decodeShellANSIQuotes(value)
	value = collapseShellEscapes(value)
	return collapseShellWordQuotes(value)
}

// Decode bounded ANSI-C shell quotes used to hide command names
func decodeShellANSIQuotes(value string) string {
	var normalized strings.Builder
	normalized.Grow(len(value))
	changed := false
	for index := 0; index < len(value); {
		if index+2 >= len(value) || value[index] != '$' || value[index+1] != '\'' {
			normalized.WriteByte(value[index])
			index++
			continue
		}
		end := strings.IndexByte(value[index+2:], '\'')
		if end < 0 || end > 256 {
			normalized.WriteByte(value[index])
			index++
			continue
		}
		body := value[index+2 : index+2+end]
		decoded, ok := decodeShellANSIBody(body)
		if !ok {
			normalized.WriteString(value[index : index+3+end])
			index += end + 3
			continue
		}
		normalized.WriteString(decoded)
		index += end + 3
		changed = true
	}
	if !changed {
		return value
	}
	return normalized.String()
}

// Interpret only fixed-width hexadecimal escapes and ordinary quoted bytes
func decodeShellANSIBody(value string) (string, bool) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) || value[index+1] != 'x' {
			return "", false
		}
		high, highOK := hexNibble(value[index+2])
		low, lowOK := hexNibble(value[index+3])
		if !highOK || !lowOK {
			return "", false
		}
		decoded.WriteByte(high<<4 | low)
		index += 3
	}
	return decoded.String(), true
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

// Match raw and derived variants without modifying the sources
func firstDerivedRegexMatch(sources []detectionSource, patterns []*regexp.Regexp, derive func(string) string) (detectionMatch, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			candidates := [...]string{variant, derive(variant)}
			for index, candidate := range candidates {
				if index == 1 && candidate == variant {
					continue
				}
				for _, pattern := range patterns {
					if location := pattern.FindStringIndex(candidate); location != nil {
						return evidenceMatch(source.name, candidate, location[0]), true
					}
				}
			}
		}
	}
	return detectionMatch{}, false
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
func firstXSSMatch(sources []detectionSource) (detectionMatch, confidence) {
	xssSources := mergeXSSDetectionVariants(sources)
	xssSources = sourcesWithMarker(xssSources, func(value string) bool { return strings.ContainsAny(value, "<:") || strings.Contains(value, "on") })
	if source, ok := firstRegexMatch(xssSources, xssActiveTagRegex, xssEventHandlerRegex, xssTagEventHandlerRegex, xssSVGAnimationHandlerRegex); ok {
		return source, confidenceHigh
	}
	if source, ok := firstRegexMatch(xssSources, xssAmbiguousTagRegex); ok {
		return source, confidenceMedium
	}
	if source, ok := firstDerivedRegexMatch(xssSources, []*regexp.Regexp{xssJavaScriptURIRegex, xssVBScriptURIRegex}, removeURLIgnoredControls); ok {
		return source, confidenceMedium
	}
	return detectionMatch{}, ""
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

// Expand nested JNDI tricks and distinguish explicit lookups from bare probes
func firstJNDIMatch(sources []detectionSource) (detectionMatch, confidence) {
	mediumSource := detectionMatch{}
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			if !strings.Contains(variant, "jndi") && !strings.Contains(variant, "${") {
				continue
			}
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
				return evidenceMatch(source.name, candidate, max(0, strings.Index(candidate, "jndi"))), confidenceHigh
			}
			if mediumSource.source == "" && jndiProtocolRegex.MatchString(candidate) {
				mediumSource = evidenceMatch(source.name, candidate, max(0, strings.Index(candidate, "jndi")))
			}
		}
	}
	if mediumSource.source != "" {
		return mediumSource, confidenceMedium
	}
	return detectionMatch{}, ""
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

// Find NoSQL operators in decoded fields
func firstNoSQLMatch(sources []detectionSource) (detectionMatch, confidence) {
	best := confidence("")
	match := detectionMatch{}
	for _, source := range sources {
		for _, candidate := range source.variants {
			if source.expired() {
				break
			}
			if !strings.Contains(candidate, "$") && !strings.Contains(candidate, `\u`) {
				continue
			}
			value := maxConfidence(noSQLJSONConfidence(candidate), noSQLParameterConfidence(candidate))
			if confidenceRank(value) > confidenceRank(best) {
				best = value
				match = evidenceMatch(source.name, candidate, noSQLEvidenceOffset(candidate, best))
			}
			if best == confidenceHigh {
				return match, best
			}
		}
	}
	return match, best
}

// Prefer an operator key over an earlier mention inside a JSON value
func noSQLEvidenceOffset(value string, best confidence) int {
	for _, location := range noSQLJSONKeyRegex.FindAllStringIndex(value, -1) {
		literal, _, _ := strings.Cut(strings.TrimSpace(value[location[0]:location[1]]), ":")
		var key string
		if json.Unmarshal([]byte(strings.TrimSpace(literal)), &key) == nil && noSQLKeyConfidence(key) == best {
			return location[0]
		}
	}
	return max(0, strings.IndexByte(value, '$'))
}

// Read operators from JSON objects
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
	case string:
		if strings.HasPrefix(strings.TrimSpace(typed), "{") || strings.HasPrefix(strings.TrimSpace(typed), "[") {
			best = noSQLJSONConfidence(typed)
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

// Read operators from parameter keys and JSON values
func noSQLParameterConfidence(value string) confidence {
	best := confidence("")
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == ';' }) {
		key, candidate, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found {
			continue
		}
		best = maxConfidence(best, noSQLKeyConfidence(key))
		best = maxConfidence(best, noSQLJSONConfidence(candidate))
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
		case "$set", "$unset", "$inc", "$push", "$pull", "$rename", "$lookup", "$group", "$match", "$out", "$merge", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex", "$exists",
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
