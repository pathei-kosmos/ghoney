package main

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Find XML entity and include probes
func firstXMLMatch(sources []detectionSource) (detectionMatch, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			if !strings.Contains(variant, "<") {
				continue
			}
			if isXMLAttack(variant) || source.name == "decoded JSON body" && isXMLAttack(strings.ReplaceAll(variant, `\"`, `"`)) {
				return evidenceMatch(source.name, variant, max(0, strings.Index(variant, "<!"))), true
			}
		}
	}
	return detectionMatch{}, false
}

// Match explicit and ambiguous URL sinks at separate confidence levels
func firstSSRFMatch(sources []detectionSource) (detectionMatch, confidence) {
	sources = sourcesWithMarker(sources, hasTargetMarker)
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			if offset := capturedValueOffset(variant, ssrfHighAssignmentRegex, isLocalTarget); offset >= 0 {
				return evidenceMatch(source.name, variant, offset), confidenceHigh
			}
		}
	}
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			for _, pattern := range []*regexp.Regexp{ssrfHighAssignmentRegex, ssrfMediumAssignmentRegex, directURLTargetRegex} {
				if pattern == directURLTargetRegex && source.name == "decoded JSON body" {
					continue
				}
				if offset := capturedValueOffset(variant, pattern, isPotentialLocalTarget); offset >= 0 {
					return evidenceMatch(source.name, variant, offset), confidenceMedium
				}
			}
		}
	}
	return detectionMatch{}, ""
}

// Match contextual file targets before ambiguous remote include probes
func firstFileInclusionMatch(sources []detectionSource) (detectionMatch, confidence) {
	sources = sourcesWithMarker(sources, func(value string) bool { return strings.ContainsAny(value, "/\\.:") })
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			for _, pattern := range []*regexp.Regexp{fileAssignmentRegex, fileJSONAssignmentRegex} {
				if offset := capturedValueOffset(variant, pattern, isFileInclusionTarget); offset >= 0 {
					return evidenceMatch(source.name, variant, offset), confidenceHigh
				}
			}
			if offset := directLocalFileProbeOffset(variant, strings.Contains(source.name, "body")); offset >= 0 {
				return evidenceMatch(source.name, variant, offset), confidenceHigh
			}
		}
	}
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			if offset := capturedValueOffset(variant, remoteFileURLRegex, isRemoteFileInclusionTarget); offset >= 0 {
				return evidenceMatch(source.name, variant, offset), confidenceMedium
			}
		}
	}
	return detectionMatch{}, ""
}

// Skip fields without target markers
func hasTargetMarker(value string) bool {
	if ssrfShortParameterRegex.MatchString(value) {
		return true
	}
	if strings.ContainsAny(value, ":./\\") {
		return true
	}
	for _, marker := range []string{"url", "uri", "link", "redirect", "next", "target", "dest", "callback", "continue", "return", "endpoint", "proxy", "fetch", "webhook", "remote", "host", "src", "image", "img", "feed", "u=", "site", "load", "ref", "goto", "r=", "open"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

// Recognize external XML features and large entity expansion
func isXMLAttack(value string) bool {
	return xmlExternalEntityRegex.MatchString(value) ||
		xmlExternalDoctypeRegex.MatchString(value) ||
		xmlIncludeRegex.MatchString(value) ||
		hasDangerousEntityExpansion(value)
}

// Detect entity cycles and growth without resolving content
func hasDangerousEntityExpansion(value string) bool {
	definitions := make(map[string]string)
	for _, match := range xmlEntityDeclaration.FindAllStringSubmatch(value, -1) {
		if len(match) != 5 {
			continue
		}
		name := match[2]
		if strings.TrimSpace(match[1]) != "" {
			name = "%" + name
		}
		entityValue := match[3]
		if entityValue == "" {
			entityValue = match[4]
		}
		definitions[name] = entityValue
	}

	states := make(map[string]uint8, len(definitions))
	sizes := make(map[string]int, len(definitions))
	for name := range definitions {
		expandedSize, dangerous := expandedEntitySize(name, definitions, states, sizes)
		if dangerous || expandedSize >= minXMLExpansionSignalSize && expandedSize >= len(definitions[name])*4 {
			return true
		}
	}
	return false
}

// Accept remote file URL schemes
func isRemoteFileInclusionTarget(candidate string) bool {
	parsed, err := url.Parse(strings.TrimSpace(candidate))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ftp", "tftp":
		return true
	default:
		return false
	}
}

// Measure one entity expansion with cycle detection
func expandedEntitySize(name string, definitions map[string]string, states map[string]uint8, sizes map[string]int) (int, bool) {
	switch states[name] {
	case 1:
		return 0, true
	case 2:
		return sizes[name], false
	}

	states[name] = 1
	value := definitions[name]
	size := 0
	cursor := 0
	for _, match := range xmlEntityReference.FindAllStringSubmatchIndex(value, -1) {
		var dangerous bool
		size, dangerous = addXMLExpansionSize(size, match[0]-cursor)
		if dangerous {
			return size, true
		}

		reference := value[match[4]:match[5]]
		if value[match[2]:match[3]] == "%" {
			reference = "%" + reference
		}
		referenceSize := match[1] - match[0]
		if _, exists := definitions[reference]; exists {
			referenceSize, dangerous = expandedEntitySize(reference, definitions, states, sizes)
			if dangerous {
				return referenceSize, true
			}
		}
		size, dangerous = addXMLExpansionSize(size, referenceSize)
		if dangerous {
			return size, true
		}
		cursor = match[1]
	}

	var dangerous bool
	size, dangerous = addXMLExpansionSize(size, len(value)-cursor)
	if dangerous {
		return size, true
	}
	states[name] = 2
	sizes[name] = size
	return size, false
}

// Stop counting once expansion crosses the threshold
func addXMLExpansionSize(size, addition int) (int, bool) {
	if addition > maxXMLExpansionSize-size {
		return maxXMLExpansionSize + 1, true
	}
	return size + addition, false
}

// Avoid counting command arguments as file probes
func hasCommandExecutionPattern(value string) bool {
	for _, pattern := range [...]*regexp.Regexp{
		commandAmbiguousSeparatorRegex,
		commandExplicitSeparatorRegex,
		commandStrongSeparatorRegex,
		commandSubstitutionRegex,
		commandAssignmentRegex,
	} {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// Match local targets outside command and XML contexts
func directLocalFileProbeOffset(value string, body bool) int {
	if body && isXMLAttack(value) {
		return -1
	}
	for offset := 0; offset < len(value); {
		match := localFileRegex.FindStringIndex(value[offset:])
		if match == nil {
			return -1
		}
		start := offset + match[0]
		end := offset + match[1]
		contextStart := strings.LastIndexAny(value[:start], "&,") + 1
		context := value[contextStart:end]
		if !pathTraversalRegex.MatchString(context) && !hasCommandExecutionPattern(context) {
			return start
		}
		offset = end
	}
	return -1
}

// Scan every capture without keeping a large match slice
func capturedValueOffset(value string, pattern *regexp.Regexp, accept func(string) bool) int {
	for offset := 0; offset < len(value); {
		match := pattern.FindStringSubmatchIndex(value[offset:])
		if match == nil {
			return -1
		}
		if len(match) >= 4 && match[2] >= 0 && accept(value[offset+match[2]:offset+match[3]]) {
			return offset + match[2]
		}
		if match[1] <= 0 {
			return -1
		}
		offset += match[1]
	}
	return -1
}

// Classify URL targets without DNS lookups
func isLocalTarget(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if strings.HasPrefix(strings.ToLower(candidate), "jar:") {
		return isLocalTarget(nestedJARTarget(candidate))
	}
	parsed, ok := parseDetectionTarget(candidate)
	if !ok {
		return false
	}
	switch parsed.Scheme {
	case "file":
		return true
	case "http", "https", "ftp", "gopher", "dict", "ldap":
	default:
		return false
	}
	return isRecognizedLocalHost(parsed.Hostname())
}

// Accept uncommon protocols and intranet hostnames at medium confidence
func isPotentialLocalTarget(candidate string) bool {
	if isLocalTarget(candidate) {
		return true
	}
	candidate = strings.TrimSpace(candidate)
	if strings.HasPrefix(strings.ToLower(candidate), "jar:") {
		return isPotentialLocalTarget(nestedJARTarget(candidate))
	}
	normalizedCandidate := normalizeSpecialURL(strings.TrimSpace(candidate))
	parsed, ok := parseDetectionTarget(candidate)
	if !ok || parsed.Scheme == "file" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if isRecognizedLocalHost(host) || isReservedDetectionHost(host) {
		return true
	}
	if host == "" {
		return false
	}
	looksLikeURL := strings.Contains(normalizedCandidate, "://") || strings.Contains(normalizedCandidate, ":")
	looksLikeMalformedNumber := strings.HasPrefix(host, "0x") || host[0] >= '0' && host[0] <= '9'
	return looksLikeURL && !strings.Contains(host, ".") && net.ParseIP(host) == nil && !looksLikeMalformedNumber
}

// Extract the nested URL before a JAR entry delimiter
func nestedJARTarget(candidate string) string {
	nested := strings.TrimSpace(candidate[len("jar:"):])
	if target, _, found := strings.Cut(nested, "!"); found {
		return strings.TrimSpace(target)
	}
	return nested
}

// Recognize special-use IPv4 ranges
func isReservedDetectionHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseLooseIPv4(host)
	}
	if ip == nil {
		return false
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	return ipv4[0] == 192 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] != 9 && ipv4[3] != 10 ||
		ipv4[0] >= 240 ||
		ipv4[0] == 198 && ipv4[1]&0xfe == 18 ||
		ipv4[0] == 192 && ipv4[1] == 0 && ipv4[2] == 2 ||
		ipv4[0] == 198 && ipv4[1] == 51 && ipv4[2] == 100 ||
		ipv4[0] == 203 && ipv4[1] == 0 && ipv4[2] == 113
}

// Parse URL targets consistently without resolving names
func parseDetectionTarget(candidate string) (*url.URL, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return nil, false
	}
	candidate = normalizeSpecialURL(candidate)
	if strings.HasPrefix(candidate, "//") {
		candidate = "http:" + candidate
	} else if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	return parsed, err == nil
}

// Recognize local hosts after URL parsing
func isRecognizedLocalHost(rawHost string) bool {
	host := strings.ToLower(strings.TrimSuffix(rawHost, "."))

	if zoneIndex := strings.LastIndexByte(host, '%'); zoneIndex >= 0 {
		host = host[:zoneIndex]
	}
	if host == "" {
		return false
	}
	switch host {
	case "localhost", "localhost.localdomain", "localtest.me",
		"metadata.google.internal", "instance-data.ec2.internal",
		"168.63.129.16":
		return true
	}
	for _, suffix := range [...]string{".localhost", ".local", ".localdomain", ".internal", ".svc", ".cluster.local", ".localtest.me"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseLooseIPv4(host)
	}
	if ip != nil {
		return isLocalIP(ip)
	}
	for _, suffix := range [...]string{".nip.io", ".sslip.io"} {
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		encodedHost := strings.TrimSuffix(host, suffix)
		for _, candidate := range [...]string{encodedHost, strings.ReplaceAll(encodedHost, "-", ".")} {
			if ip := parseLooseIPv4(candidate); ip != nil && isLocalIP(ip) {
				return true
			}
		}
	}
	return false
}

// Align special URL separators with browser and common client parsing
func normalizeSpecialURL(candidate string) string {
	if strings.HasPrefix(candidate, `\\`) {
		return "//" + strings.TrimLeft(strings.ReplaceAll(candidate, `\`, "/"), "/")
	}
	separator := strings.IndexByte(candidate, ':')
	if separator <= 0 {
		return candidate
	}
	scheme := strings.ToLower(candidate[:separator])
	switch scheme {
	case "http", "https", "ftp":
	default:
		return candidate
	}
	remainder := strings.ReplaceAll(candidate[separator+1:], `\`, "/")
	remainder = strings.TrimLeft(remainder, "/")
	return scheme + "://" + remainder
}

// Classify parsed addresses without touching the network
func isLocalIP(ip net.IP) bool {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
		if ipv4[0] == 100 && ipv4[1]&0xc0 == 0x40 || ipv4[0] == 0 {
			return true
		}
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// Parse legacy IPv4 forms with one to four parts
func parseLooseIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for index, part := range parts {
		value, ok := parseIPv4Part(part)
		if !ok {
			return nil
		}
		values[index] = value
	}

	var address uint64
	switch len(values) {
	case 1:
		if values[0] > 0xffffffff {
			return nil
		}
		address = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil
		}
		address = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil
		}
		address = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, value := range values {
			if value > 0xff {
				return nil
			}
		}
		address = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}
	return net.IPv4(byte(address>>24), byte(address>>16), byte(address>>8), byte(address))
}

// Parse decimal, octal and hexadecimal IPv4 parts
func parseIPv4Part(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	base := 10
	digits := part
	switch {
	case strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X"):
		base = 16
		digits = part[2:]
	case len(part) > 1 && part[0] == '0':
		base = 8
		digits = part[1:]
	}
	if digits == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(digits, base, 32)
	return value, err == nil
}

// Restrict inclusion checks to file parameters and usable targets
func isFileInclusionTarget(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if localFileRegex.MatchString(candidate) {
		return true
	}
	if strings.HasPrefix(candidate, "//") || strings.HasPrefix(candidate, `\\`) {
		return true
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	switch parsed.Scheme {
	case "http", "https", "ftp", "tftp", "data":
		return true
	default:
		return false
	}
}
