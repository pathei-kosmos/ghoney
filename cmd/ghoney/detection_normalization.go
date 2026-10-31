package main

import (
	"bytes"
	"context"
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

// Preserve complete accepted fields under a shared input budget
func buildDetectionSourcesContext(ctx context.Context, input detectionInput) []detectionSource {
	sources := make([]detectionSource, 0, 20)
	remaining := maxDetectionInputSize
	type sourceKey struct {
		name, key, value string
		plusAsSpace      bool
	}
	seenSources := make(map[sourceKey]struct{})
	appendSource := func(name, key, value string, plusAsSpace bool) {
		if value == "" && key == "" || remaining <= 0 || ctx.Err() != nil {
			return
		}
		value = value[:min(len(value), remaining, maxDetectionSourceSize)]
		identity := sourceKey{name, key, value, plusAsSpace}
		if _, exists := seenSources[identity]; exists {
			return
		}
		seenSources[identity] = struct{}{}
		remaining -= len(value)
		variants, xssVariants := decodeFieldVariants(ctx, key, value, plusAsSpace)
		if len(variants) > 0 {
			sources = append(sources, detectionSource{name: name, ctx: ctx, variants: variants, xssVariants: xssVariants})
		}
	}
	appendFields := func(name string, fields []detectionField, encodedOnly bool) {
		for _, field := range fields {
			if encodedOnly {
				if _, ok := decodeBase64Text(field.value); !ok && !strings.ContainsAny(field.value, "%&") {
					continue
				}
			}
			appendSource(name, field.key, field.value, false)
		}
	}
	appendSource("request path", "", input.Path, false)
	appendSource("query string", "", input.RawQuery, true)
	appendFields("query string", detectionParameterFields(truncateDetectionSource(input.RawQuery)), true)
	body := input.Body[:min(len(input.Body), maxRequestBodySize)]
	// Keep valid undeclared gzip streams out of text matching
	if hasGzipSignature([]byte(body)) {
		if _, err := readSingleBoundedGzipBody([]byte(body)); err == nil {
			body = ""
		}
	}
	contentType := input.Header.Get("Content-Type")
	switch {
	case isMultipartContentType(contentType):
		if fields, ok := parseMultipartTextFields(body, contentType); ok {
			appendFields("request body", fields, false)
		} else if isLikelyDetectionText(body) {
			appendSource("request body", "", body, false)
		}
	case isLikelyDetectionText(body):
		appendSource("request body", "", body, isFormContentType(contentType))
		if isFormContentType(contentType) {
			appendFields("request body", detectionParameterFields(body), true)
		}
	default:
		// Scan text runs without treating binary bytes as syntax
		for _, run := range strings.FieldsFunc(body, func(r rune) bool {
			return r == unicode.ReplacementChar || !unicode.IsPrint(r) && r != '\t' && r != '\n' && r != '\r'
		}) {
			if len(run) >= minBinaryTextRunSize {
				appendSource("request body", "", run, false)
			}
		}
	}
	if decoded, ok := decodeUnicodeText([]byte(body)); ok {
		appendSource("decoded Unicode body", "", decoded, false)
	}
	if isJSONContentType(contentType) {
		if decoded, ok := decodeJSONStringLiterals(body); ok {
			appendSource("decoded JSON body", "", decoded, false)
		}
		var document any
		if json.Unmarshal([]byte(body), &document) == nil {
			fields := make([]detectionField, 0)
			collectJSONFields(document, "", &fields)
			appendFields("request body", fields, true)
		}
	}
	appendSource("Host header", "", input.Host, false)
	// Sort headers for consistent match selection
	names := make([]string, 0, len(input.Header))
	for name := range input.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	headerBudget := maxDetectionSourceSize
	for _, name := range names {
		for _, value := range input.Header[name] {
			// A valid HTTP field needs only a colon and CRLF beyond its name and value
			headerBudget -= len(name) + 3
			if headerBudget <= 0 {
				return sources
			}
			value = value[:min(len(value), headerBudget)]
			headerBudget -= len(value)
			appendSource(name+" header", "", value, false)
			if strings.EqualFold(name, "Cookie") {
				appendFields(name+" header", detectionParameterFields(value), true)
			} else if strings.EqualFold(name, "Authorization") {
				if _, token, found := strings.Cut(strings.TrimSpace(value), " "); found {
					appendSource("decoded Authorization header", "", token, false)
				}
			}
		}
	}
	return sources
}

// Keep parameter values separate and preserve literal plus signs for Base64
func detectionParameterFields(value string) []detectionField {
	value = html.UnescapeString(value)
	fields := make([]detectionField, 0)
	seenFields := make(map[string]struct{})
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == ';' }) {
		if _, exists := seenFields[field]; exists {
			continue
		}
		seenFields[field] = struct{}{}
		key, encoded, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		decodedKey, keyErr := url.QueryUnescape(strings.TrimSpace(key))
		decodedValue, valueErr := url.PathUnescape(strings.TrimSpace(encoded))
		if keyErr == nil && valueErr == nil {
			fields = append(fields, detectionField{key: decodedKey, value: decodedValue})
		}
	}
	return fields
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

// Parse text parts once within the accepted request body budget
func parseMultipartTextFields(value, contentType string) ([]detectionField, bool) {
	_, parameters, err := mime.ParseMediaType(contentType)
	boundary := parameters["boundary"]
	if err != nil || boundary == "" {
		return nil, false
	}

	reader := multipart.NewReader(strings.NewReader(value), boundary)
	fields := make([]detectionField, 0)
	remaining := maxRequestBodySize
	for remaining > 0 {
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, false
		}
		if disposition, parameters, err := mime.ParseMediaType(part.Header.Get("Content-Disposition")); err == nil && disposition == "form-data" && parameters["filename"] != "" {
			fields = append(fields, detectionField{key: "filename", value: parameters["filename"]})
		}
		// Inspect textual uploads as well as fields within the same total budget
		payload, readErr := io.ReadAll(io.LimitReader(part, int64(remaining+1)))
		closeErr := part.Close()
		if readErr != nil || closeErr != nil || len(payload) > remaining {
			return nil, false
		}
		remaining -= len(payload)
		if len(payload) == 0 || isLikelyDetectionText(string(payload)) {
			fields = append(fields, detectionField{key: part.FormName(), value: string(payload)})
		}
	}
	return fields, true
}

// Keep key context for decoded command and URL assignments
type detectionField struct {
	key   string
	value string
}

// Collect JSON string values in stable key order
func collectJSONFields(value any, key string, fields *[]detectionField) {
	switch typed := value.(type) {
	case string:
		*fields = append(*fields, detectionField{key: key, value: typed})
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for childKey := range typed {
			keys = append(keys, childKey)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			collectJSONFields(typed[childKey], childKey, fields)
		}
	case []any:
		for _, child := range typed {
			collectJSONFields(child, key, fields)
		}
	}
}

// Decode before case folding to preserve Base64
func decodeFieldVariants(ctx context.Context, key, value string, plusAsSpace bool) ([]string, []string) {
	variants := make([]string, 0, 4)
	xssVariants := make([]string, 0)
	seen := make(map[string]struct{})
	decodedSeen := make(map[string]struct{})
	queue := []string{value}
	remainingWork := maxDetectionDecodeWorkSize
	for cursor := 0; cursor < len(queue) && cursor < maxNormalizationVariants; cursor++ {
		if ctx.Err() != nil {
			break
		}
		current := queue[cursor]
		if len(current) > remainingWork || len(variants) >= maxNormalizationVariants {
			break
		}
		if _, exists := decodedSeen[current]; exists {
			continue
		}
		decodedSeen[current] = struct{}{}
		remainingWork -= len(current)
		candidate := current
		if key != "" {
			candidate = key + "=" + current
		}
		canonical := canonicalizeDetectionText(candidate)
		appendUniqueVariant(&variants, seen, canonical)
		if len(variants) < maxNormalizationVariants {
			appendUniqueVariant(&variants, seen, strings.Join(strings.Fields(canonical), " "))
		}
		// Use decoded browser documents only for XSS checks
		if strings.Contains(strings.ToLower(current), "data:") {
			xssVariants = appendXSSDataURIVariants(xssVariants, current, plusAsSpace)
		}
		decoded := html.UnescapeString(current)
		preserved, _ := decodeDetectionEscapes(decoded, false)
		if preserved != current {
			queue = append(queue, preserved)
		}
		if plusAsSpace && strings.Contains(decoded, "+") {
			spaced, _ := decodeDetectionEscapes(decoded, true)
			if spaced != current && spaced != preserved {
				queue = append(queue, spaced)
			}
		}
		if decoded, ok := decodeBase64Text(current); ok {
			queue = append(queue, decoded)
		}
	}
	return variants, xssVariants
}

// Decode active data documents for XSS matching
func appendXSSDataURIVariants(variants []string, value string, plusAsSpace bool) []string {
	if len(variants) >= maxNormalizationVariants {
		return variants
	}
	seenVariants := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		seenVariants[variant] = struct{}{}
	}
	seenPayloads := make(map[string]struct{})
	remainingOutput := maxRequestBodySize
	remainingDecodeWork := maxDetectionDecodeWorkSize
	current := truncateDetectionSource(value)

	for remainingOutput > 0 && len(variants) < maxNormalizationVariants && len(current) <= remainingDecodeWork {
		remainingDecodeWork -= len(current)
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
			for payloadStart < len(current) && (current[payloadStart] == ' ' || current[payloadStart] == '\t' || current[payloadStart] == '\r' || current[payloadStart] == '\n') {
				payloadStart++
			}
			payloadEnd := payloadStart
			for payloadEnd < len(current) && (isBase64DataByte(current[payloadEnd]) || current[payloadEnd] == '\r' || current[payloadEnd] == '\n') {
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
				if len(variants) >= maxNormalizationVariants {
					break
				}
				appendUniqueVariant(&variants, seenVariants, variant)
			}
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

// Accept textual bodies while excluding compressed and other binary payloads
func isLikelyDetectionText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	printable := 0
	total := 0
	for _, current := range value {
		total++
		if current == '\t' || current == '\n' || current == '\r' || unicode.IsPrint(current) {
			printable++
		}
	}
	return total > 0 && printable*10 >= total*9
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

// Decode one complete textual Base64 value without recursion
func decodeBase64Text(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < minBase64ValueSize || len(value) > maxDetectionSourceSize {
		return "", false
	}
	// Reject non-alphabet bytes before trying multiple Base64 alphabets
	for index := 0; index < len(value); index++ {
		if !isBase64DataByte(value[index]) && value[index] != '\r' && value[index] != '\n' {
			return "", false
		}
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

// Keep raw and decoded forms within the decoding limits
func normalizeDetectionVariants(value string, plusAsSpace bool) []string {
	value = truncateDetectionSource(value)
	if value == "" {
		return nil
	}

	variants := make([]string, 0, maxNormalizationVariants)
	seen := make(map[string]struct{}, cap(variants))
	current := value
	remainingWork := maxDetectionDecodeWorkSize
	for len(variants) < maxNormalizationVariants && len(current) <= remainingWork {
		remainingWork -= len(current)
		canonical := canonicalizeDetectionText(current)
		appendUniqueVariant(&variants, seen, canonical)
		if len(variants) < maxNormalizationVariants {
			appendUniqueVariant(&variants, seen, strings.Join(strings.Fields(canonical), " "))
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

// Return the first match and its source
func firstRegexMatch(sources []detectionSource, patterns ...*regexp.Regexp) (detectionMatch, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			for _, pattern := range patterns {
				if location := pattern.FindStringIndex(variant); location != nil {
					offset := location[0]
					if pattern == xssTagEventHandlerRegex {
						if handler := xssAnyEventHandlerRegex.FindStringIndex(variant[location[0]:location[1]]); handler != nil {
							offset += handler[0]
						}
					}
					return evidenceMatch(source.name, variant, offset), true
				}
			}
		}
	}
	return detectionMatch{}, false
}

// Keep a short sample around the match
func evidenceMatch(source, value string, offset int) detectionMatch {
	start := max(0, offset-48)
	if start > len(value) {
		start = 0
	}
	return detectionMatch{source: source, sample: truncateUTF8(value[start:], maxBodySnippetSize)}
}

// Skip variants without markers for this family
func sourcesWithMarker(sources []detectionSource, accept func(string) bool) []detectionSource {
	filtered := make([]detectionSource, 0, len(sources))
	for _, source := range sources {
		variants := make([]string, 0, len(source.variants))
		for _, variant := range source.variants {
			if source.expired() {
				break
			}
			if accept(variant) {
				variants = append(variants, variant)
			}
		}
		if len(variants) > 0 {
			source.variants = variants
			filtered = append(filtered, source)
		}
	}
	return filtered
}
