package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Build bounded variants without mixing request fields
func buildDetectionSources(input detectionInput) []detectionSource {
	sources := make([]detectionSource, 0, maxDetectionSources)
	appendDetectionSource := func(name, value string, plusAsSpace bool) {
		if value == "" || len(sources) >= maxDetectionSources {
			return
		}
		boundedValue := truncateDetectionSource(value)
		variants := normalizeDetectionVariants(boundedValue, plusAsSpace)
		xssVariants := appendXSSDataURIVariants(nil, boundedValue, plusAsSpace)
		switch name {
		case "query string":
			variants = appendBase64ParameterVariants(variants, boundedValue)
		case "request body":
			switch {
			case isFormContentType(input.Header.Get("Content-Type")):
				variants = appendBase64ParameterVariants(variants, boundedValue)
			case isJSONContentType(input.Header.Get("Content-Type")):
				variants = appendBase64JSONVariants(variants, boundedValue)
			case isMultipartContentType(input.Header.Get("Content-Type")):
				variants = appendBase64MultipartVariants(variants, boundedValue, input.Header.Get("Content-Type"))
			}
		}
		if len(variants) > 0 {
			sources = append(sources, detectionSource{name: name, variants: variants, xssVariants: xssVariants})
		}
	}

	appendDetectionSource("request path", input.Path, false)
	appendDetectionSource("query string", input.RawQuery, true)
	appendDetectionSource("request body", input.Body, isFormContentType(input.Header.Get("Content-Type")))
	if decoded, ok := decodeUnicodeText([]byte(input.Body)); ok {
		appendDetectionSource("decoded Unicode body", decoded, false)
	}
	if isJSONContentType(input.Header.Get("Content-Type")) {
		if decoded, ok := decodeJSONStringLiterals(input.Body); ok {
			appendDetectionSource("decoded JSON body", decoded, false)
		}
	}
	appendDetectionSource("Host header", input.Host, false)
	if decoded, ok := decodeBasicAuthorization(input.Header.Get("Authorization")); ok {
		appendDetectionSource("decoded Authorization header", decoded, false)
	}

	for _, name := range inspectedHeaderNames {
		if len(sources) >= maxDetectionSources {
			return sources
		}
		values := input.Header.Values(name)
		if len(values) > 0 {
			variants, xssVariants := normalizeDetectionHeaderValues(name, values)
			if len(variants) > 0 {
				sources = append(sources, detectionSource{name: name + " header", variants: variants, xssVariants: xssVariants})
			}
		}
	}
	return sources
}

// Normalize repeated header values within the server read budget
func normalizeDetectionHeaderValues(name string, values []string) ([]string, []string) {
	variants := make([]string, 0, (maxDecodePasses+1)*2)
	xssVariants := make([]string, 0)
	seen := make(map[string]struct{}, cap(variants))
	remaining := maxDetectionSourceSize
	lineOverhead := len(name) + 4

	for _, value := range values {
		available := remaining - lineOverhead
		if available <= 0 {
			break
		}
		remaining = available
		if len(value) > available {
			value = sampleHeaderEdges(value, available)
			remaining = 0
		} else {
			remaining -= len(value)
		}
		for _, variant := range normalizeDetectionVariants(value, false) {
			appendUniqueVariant(&variants, seen, variant)
		}
		xssVariants = appendXSSDataURIVariants(xssVariants, value, false)
	}
	return variants, xssVariants
}

// Preserve both ends when a header exceeds the HTTP read window
func sampleHeaderEdges(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	if limit == 1 {
		return value[len(value)-1:]
	}
	prefixSize := (limit - 1) / 2
	suffixSize := limit - prefixSize - 1
	return value[:prefixSize] + " " + value[len(value)-suffixSize:]
}

// Recognize form encoding while ignoring optional parameters
func isFormContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	return strings.TrimSpace(contentType) == "application/x-www-form-urlencoded"
}

// Match JSON media types while ignoring optional parameters
func isJSONContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	contentType = strings.TrimSpace(contentType)
	return contentType == "application/json" || strings.HasSuffix(contentType, "+json")
}

// Recognize multipart forms and leave malformed values to the raw scanner
func isMultipartContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, "multipart/form-data")
}

// Add bounded decoded values without joining independent fields
func appendBase64ParameterVariants(variants []string, value string) []string {
	fields := make([]base64Field, 0)
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == ';' }) {
		key, encoded, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		decodedKey, keyErr := url.QueryUnescape(strings.TrimSpace(key))
		decodedValue, valueErr := url.QueryUnescape(strings.TrimSpace(encoded))
		if keyErr != nil || valueErr != nil {
			continue
		}
		fields = append(fields, base64Field{key: decodedKey, value: decodedValue})
	}
	return appendBase64FieldVariants(variants, fields)
}

// Add decoded JSON string values in stable key order
func appendBase64JSONVariants(variants []string, value string) []string {
	if len(value) > maxRequestBodySize || !json.Valid([]byte(value)) {
		return variants
	}
	var document any
	if err := json.Unmarshal([]byte(value), &document); err != nil {
		return variants
	}
	fields := make([]base64Field, 0)
	collectBase64JSONFields(document, "", &fields)
	return appendBase64FieldVariants(variants, fields)
}

// Decode bounded multipart text fields and keep their assignment context
func appendBase64MultipartVariants(variants []string, value, contentType string) []string {
	fields, ok := parseMultipartTextFields(value, contentType)
	if !ok {
		return variants
	}
	variants = appendRawFieldVariants(variants, fields)
	return appendBase64FieldVariants(variants, fields)
}

// Parse text parts once within the accepted request body budget
func parseMultipartTextFields(value, contentType string) ([]base64Field, bool) {
	_, parameters, err := mime.ParseMediaType(contentType)
	boundary := parameters["boundary"]
	if err != nil || boundary == "" {
		return nil, false
	}

	reader := multipart.NewReader(strings.NewReader(value), boundary)
	fields := make([]base64Field, 0)
	remaining := maxRequestBodySize
	for remaining > 0 {
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, false
		}
		if part.FileName() != "" {
			_ = part.Close()
			continue
		}
		payload, readErr := io.ReadAll(io.LimitReader(part, int64(remaining+1)))
		closeErr := part.Close()
		if readErr != nil || closeErr != nil || len(payload) > remaining {
			return nil, false
		}
		remaining -= len(payload)
		fields = append(fields, base64Field{key: part.FormName(), value: string(payload)})
	}
	return fields, true
}

// Keep key context for decoded command and URL assignments
type base64Field struct {
	key   string
	value string
}

// Add raw key-value forms so contextual detectors see multipart fields
func appendRawFieldVariants(variants []string, fields []base64Field) []string {
	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		seen[variant] = struct{}{}
	}
	remaining := maxRequestBodySize
	for _, field := range fields {
		if field.key == "" || len(field.key)+len(field.value)+1 > remaining {
			continue
		}
		remaining -= len(field.key) + len(field.value) + 1
		for _, variant := range normalizeDetectionVariants(field.key+"="+field.value, false) {
			appendUniqueVariant(&variants, seen, variant)
		}
	}
	return variants
}

// Walk one bounded JSON document without decoding keys
func collectBase64JSONFields(value any, key string, fields *[]base64Field) {
	switch typed := value.(type) {
	case string:
		*fields = append(*fields, base64Field{key: key, value: typed})
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for childKey := range typed {
			keys = append(keys, childKey)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			collectBase64JSONFields(typed[childKey], childKey, fields)
		}
	case []any:
		for _, child := range typed {
			collectBase64JSONFields(child, key, fields)
		}
	}
}

// Append recursively decoded Base64 values within bounded work budgets
func appendBase64FieldVariants(variants []string, fields []base64Field) []string {
	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		seen[variant] = struct{}{}
	}
	remainingInput := maxDetectionSourceSize
	remainingOutput := maxRequestBodySize
	for _, field := range fields {
		if remainingOutput <= 0 {
			break
		}
		if len(field.value) > remainingInput {
			break
		}
		remainingInput -= len(field.value)
		current := field.value
		for pass := 0; pass < maxBase64DecodePasses; pass++ {
			decoded, ok := decodeBase64Text(current)
			if !ok || len(decoded) > remainingOutput {
				break
			}
			remainingOutput -= len(decoded)
			candidate := decoded
			if field.key != "" {
				candidate = field.key + "=" + decoded
			}
			for _, variant := range normalizeDetectionVariants(candidate, false) {
				appendUniqueVariant(&variants, seen, variant)
			}
			current = decoded
		}
	}
	return variants
}

// Decode Base64 data URIs only for active browser media and only for XSS matching
func appendXSSDataURIVariants(variants []string, value string, plusAsSpace bool) []string {
	seenVariants := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		seenVariants[variant] = struct{}{}
	}
	seenPayloads := make(map[string]struct{})
	remainingOutput := maxRequestBodySize
	current := truncateDetectionSource(value)

	for pass := 0; pass <= maxDecodePasses && remainingOutput > 0; pass++ {
		for offset := 0; offset < len(current) && remainingOutput > 0; {
			location := xssDataURIPrefixRegex.FindStringIndex(current[offset:])
			if location == nil {
				break
			}
			offset += location[1]

			metadataEnd := min(len(current), offset+maxDataURIMetadataSize)
			relativeComma := strings.IndexByte(current[offset:metadataEnd], ',')
			if relativeComma < 0 {
				continue
			}
			comma := offset + relativeComma
			metadataParts := strings.Split(current[offset:comma], ";")
			if len(metadataParts) < 2 || !isActiveXSSDataMediaType(metadataParts[0]) || !strings.EqualFold(strings.TrimSpace(metadataParts[len(metadataParts)-1]), "base64") {
				continue
			}

			payloadStart := comma + 1
			for payloadStart < len(current) && (current[payloadStart] == ' ' || current[payloadStart] == '\t') {
				payloadStart++
			}
			payloadEnd := payloadStart
			for payloadEnd < len(current) && isBase64DataByte(current[payloadEnd]) {
				payloadEnd++
			}
			offset = max(offset, payloadEnd)
			decoded, ok := decodeBase64Text(current[payloadStart:payloadEnd])
			if !ok {
				continue
			}
			if _, exists := seenPayloads[decoded]; exists {
				continue
			}
			seenPayloads[decoded] = struct{}{}
			if len(decoded) > remainingOutput {
				return variants
			}
			remainingOutput -= len(decoded)
			for _, variant := range normalizeDetectionVariants(decoded, false) {
				appendUniqueVariant(&variants, seenVariants, variant)
			}
		}

		if pass == maxDecodePasses {
			break
		}
		htmlDecoded := html.UnescapeString(current)
		decoded, escaped := decodeDetectionEscapes(htmlDecoded, plusAsSpace)
		if htmlDecoded == current && (!escaped || decoded == htmlDecoded) {
			break
		}
		current = decoded
	}
	return variants
}

// Restrict data URI decoding to media types that browsers can execute as documents
func isActiveXSSDataMediaType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "text/html", "image/svg+xml", "application/xhtml+xml":
		return true
	default:
		return false
	}
}

// Accept the standard and URL-safe alphabets until the data URI delimiter
func isBase64DataByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("+/_-=", rune(value))
}

// Decode UTF-16 and UTF-32 bodies with a BOM or a clear ASCII-compatible layout
func decodeUnicodeText(value []byte) (string, bool) {
	if len(value) < 4 || len(value) > maxRequestBodySize {
		return "", false
	}

	if len(value)%4 == 0 {
		switch {
		case len(value) >= 4 && bytes.Equal(value[:4], []byte{0xff, 0xfe, 0x00, 0x00}):
			return decodeUTF32(value[4:], binary.LittleEndian)
		case len(value) >= 4 && bytes.Equal(value[:4], []byte{0x00, 0x00, 0xfe, 0xff}):
			return decodeUTF32(value[4:], binary.BigEndian)
		case looksLikeUTF32(value, binary.LittleEndian):
			return decodeUTF32(value, binary.LittleEndian)
		case looksLikeUTF32(value, binary.BigEndian):
			return decodeUTF32(value, binary.BigEndian)
		}
	}

	switch {
	case len(value) >= 2 && value[0] == 0xff && value[1] == 0xfe:
		return decodeUTF16(value[2:], binary.LittleEndian)
	case len(value) >= 2 && value[0] == 0xfe && value[1] == 0xff:
		return decodeUTF16(value[2:], binary.BigEndian)
	case looksLikeUTF16(value, binary.LittleEndian):
		return decodeUTF16(value, binary.LittleEndian)
	case looksLikeUTF16(value, binary.BigEndian):
		return decodeUTF16(value, binary.BigEndian)
	default:
		return "", false
	}
}

// Require zero high bytes in most sampled UTF-16 code units
func looksLikeUTF16(value []byte, order binary.ByteOrder) bool {
	if len(value)%2 != 0 {
		return false
	}
	units := min(len(value)/2, 32)
	zeros := 0
	for index := 0; index < units; index++ {
		unit := order.Uint16(value[index*2:])
		if unit <= 0x7f {
			zeros++
		}
	}
	return units >= 2 && zeros*4 >= units*3
}

// Require ASCII-range code points in most sampled UTF-32 units
func looksLikeUTF32(value []byte, order binary.ByteOrder) bool {
	units := min(len(value)/4, 16)
	ascii := 0
	for index := 0; index < units; index++ {
		if order.Uint32(value[index*4:]) <= 0x7f {
			ascii++
		}
	}
	return units >= 2 && ascii*4 >= units*3
}

// Decode valid UTF-16 code units and reject odd or malformed input
func decodeUTF16(value []byte, order binary.ByteOrder) (string, bool) {
	if len(value) == 0 || len(value)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(value)/2)
	for index := range units {
		units[index] = order.Uint16(value[index*2:])
	}
	decoded := string(utf16.Decode(units))
	return decoded, decoded != "" && !strings.ContainsRune(decoded, unicode.ReplacementChar)
}

// Decode valid UTF-32 code points without accepting surrogate values
func decodeUTF32(value []byte, order binary.ByteOrder) (string, bool) {
	if len(value) == 0 || len(value)%4 != 0 {
		return "", false
	}
	var decoded strings.Builder
	decoded.Grow(len(value) / 2)
	for offset := 0; offset < len(value); offset += 4 {
		current := rune(order.Uint32(value[offset:]))
		if !utf8.ValidRune(current) || current >= 0xd800 && current <= 0xdfff {
			return "", false
		}
		decoded.WriteRune(current)
	}
	return decoded.String(), decoded.Len() > 0
}

// Decode bounded credentials without requiring an application login
func decodeBasicAuthorization(value string) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found || !strings.EqualFold(scheme, "basic") {
		return "", false
	}
	return decodeBase64Text(token)
}

// Decode one complete textual Base64 value without recursion
func decodeBase64Text(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < minBase64ValueSize || len(value) > maxDetectionSourceSize {
		return "", false
	}
	encodings := [...]*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err != nil || len(decoded) == 0 || len(decoded) > maxRequestBodySize || !utf8.Valid(decoded) {
			continue
		}
		text := string(decoded)
		if isPrintableDetectionText(text) {
			return text, true
		}
	}
	return "", false
}

// Reject binary tokens that only happen to use a Base64 alphabet
func isPrintableDetectionText(value string) bool {
	for _, current := range value {
		if current != '\t' && current != '\n' && current != '\r' && !unicode.IsPrint(current) {
			return false
		}
	}
	return true
}

// Decode JSON strings while keeping the surrounding syntax
func decodeJSONStringLiterals(value string) (string, bool) {
	if value == "" || !json.Valid([]byte(value)) {
		return "", false
	}

	var decoded strings.Builder
	decoded.Grow(len(value))
	changed := false
	for offset := 0; offset < len(value); {
		if value[offset] != '"' {
			decoded.WriteByte(value[offset])
			offset++
			continue
		}

		end := offset + 1
		for end < len(value) {
			if value[end] == '\\' {
				end += 2
				continue
			}
			if value[end] == '"' {
				break
			}
			end++
		}
		if end >= len(value) {
			return "", false
		}

		var literal string
		if err := json.Unmarshal([]byte(value[offset:end+1]), &literal); err != nil {
			return "", false
		}
		decoded.WriteByte('"')
		decoded.WriteString(strings.ReplaceAll(literal, `"`, `\"`))
		decoded.WriteByte('"')
		changed = changed || literal != value[offset+1:end]
		offset = end + 1
	}
	if !changed {
		return "", false
	}
	return decoded.String(), true
}

// Keep raw and decoded forms through a fixed number of passes
func normalizeDetectionVariants(value string, plusAsSpace bool) []string {
	value = truncateDetectionSource(value)
	if value == "" {
		return nil
	}

	variants := make([]string, 0, (maxDecodePasses+1)*2)
	seen := make(map[string]struct{}, cap(variants))
	current := value
	for pass := 0; pass <= maxDecodePasses; pass++ {
		canonical := canonicalizeDetectionText(current)
		appendUniqueVariant(&variants, seen, canonical)
		appendUniqueVariant(&variants, seen, strings.Join(strings.Fields(canonical), " "))

		if pass == maxDecodePasses {
			break
		}
		htmlDecoded := html.UnescapeString(current)
		decoded, escaped := decodeDetectionEscapes(htmlDecoded, plusAsSpace)
		if htmlDecoded == current && (!escaped || decoded == htmlDecoded) {
			break
		}
		current = decoded
	}
	return variants
}

// Normalize case and common separator lookalikes while keeping newlines
func canonicalizeDetectionText(value string) string {
	value = normalizeLegacyUTF8Separators(value)
	value = strings.ToValidUTF8(value, "?")
	value = detectionRuneReplacer.Replace(value)
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.ToLower(value)
	return truncateUTF8(strings.TrimSpace(value), maxCanonicalSourceSize)
}

// Bound raw input before UTF8 repair
func truncateDetectionSource(value string) string {
	if len(value) > maxDetectionSourceSize {
		value = value[:maxDetectionSourceSize]
	}
	value = normalizeLegacyUTF8Separators(value)
	return strings.ToValidUTF8(value, "?")
}

// Recover legacy UTF8 separators before repairing invalid input
func normalizeLegacyUTF8Separators(value string) string {
	return legacyUTF8SeparatorReplacer.Replace(value)
}

// Keep malformed escapes and decode valid percent sequences
func decodeDetectionEscapes(value string, plusAsSpace bool) (string, bool) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	changed := false

	for index := 0; index < len(value); index++ {
		switch {
		case plusAsSpace && value[index] == '+':
			decoded.WriteByte(' ')
			changed = true
		case value[index] == '%' && index+5 < len(value) && (value[index+1] == 'u' || value[index+1] == 'U'):
			runeValue, ok := decodeHexRune(value[index+2 : index+6])
			if !ok {
				decoded.WriteByte(value[index])
				continue
			}
			decoded.WriteRune(runeValue)
			index += 5
			changed = true
		case value[index] == '%' && index+2 < len(value):
			high, highOK := hexNibble(value[index+1])
			low, lowOK := hexNibble(value[index+2])
			if !highOK || !lowOK {
				decoded.WriteByte(value[index])
				continue
			}
			decoded.WriteByte(high<<4 | low)
			index += 2
			changed = true
		default:
			decoded.WriteByte(value[index])
		}
	}
	return decoded.String(), changed
}

// Decode one legacy %u sequence and reject invalid runes
func decodeHexRune(value string) (rune, bool) {
	var decoded rune
	for index := 0; index < len(value); index++ {
		nibble, ok := hexNibble(value[index])
		if !ok {
			return 0, false
		}
		decoded = decoded<<4 | rune(nibble)
	}
	if !utf8.ValidRune(decoded) {
		return 0, false
	}
	return decoded, true
}

// Convert one ASCII hexadecimal digit
func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

// Append one canonical form only once
func appendUniqueVariant(variants *[]string, seen map[string]struct{}, value string) {
	if value == "" {
		return
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	*variants = append(*variants, value)
}

// Return the source of the first signature match
func firstRegexMatch(sources []detectionSource, patterns ...*regexp.Regexp) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			for _, pattern := range patterns {
				if pattern.MatchString(variant) {
					return source.name, true
				}
			}
		}
	}
	return "", false
}
