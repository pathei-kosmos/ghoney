package main

import (
	"regexp"
	"strings"
)

const (
	// Keep command groups together for every shell context
	commandCoreBinaryNames     = `whoami|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|printenv|sleep|python|python3|perl|ruby|busybox`
	commandExtendedBinaryNames = `echo|chmod|chown|cut|head|tail|grep|awk|sed|dd|find|xargs|tee|ssh|scp|socat|openssl|base64|tar|node|php|java|docker|kubectl|ipconfig|certutil|wmic|bitsadmin|mshta|rundll32|regsvr32|cscript|net|sc|type|dir`
	commandExplicitBinaryGroup = `(?:` + commandCoreBinaryNames + `|` + commandExtendedBinaryNames + `)`
	commandAllBinaryGroup      = `(?:id|env|ls|` + commandCoreBinaryNames + `|` + commandExtendedBinaryNames + `)`
	commandGenericBinaryGroup  = `(?:whoami|uname|ipconfig|certutil|wmic|bitsadmin|mshta|rundll32|regsvr32|cscript)`
	// Keep SQL operands bounded so flexible conditional signatures remain linear
	sqlScalarOperand = `(?:\(*\s*(?:\d+|0x[0-9a-f]+|'[^']{0,128}'|"[^"]{0,128}"|char\s*\(\s*(?:\d+\s*,\s*){0,15}\d+\s*\)|true|false)\s*\)*)`
)

var (
	// Compile signatures once at startup
	pathTraversalRegex             = regexp.MustCompile(`(?:\.{2,}[/\\]|\.\.;[/\\])`)
	sqlQuotedBooleanRegex          = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*(?:or|and|xor|\\|\\||&&)\\s*(?:not\\s+)?(?:\\d+|'[^']*'|\"[^\"]*\")\\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\\s*(?:\\d+|'[^']*'|\"[^\"]*\")")
	sqlTruncatedQuotedBooleanRegex = regexp.MustCompile("(?i)(?:'|\")\\)?\\s*(?:or|and|xor|\\|\\||&&)\\s*\\(?\\s*(?:'[^']{0,128}'|\"[^\"]{0,128}\")\\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\\s*(?:'[^']{0,128}|\"[^\"]{0,128})")
	sqlParenthesizedQuotedRegex    = regexp.MustCompile(`(?i)['"]\s*(?:or|and|xor)\s*\(\s*['"][^)]{1,128}\)\s*(?:=|<>|!=|>=|<=|>|<)\s*['"][^&;,\s}]{1,128}`)
	sqlNumericBooleanRegex         = regexp.MustCompile(`(?i)(?:^|[?&;\s])(?:[a-z_][a-z0-9_.-]*=)?\d+\s+(?:or|and|xor|\|\||&&)\s+\d+\s*(?:=|<>|!=|>=|<=|>|<)\s*\d+`)
	sqlCommentTailRegex            = regexp.MustCompile("(?i)(?:'|\"|`)\\s*(?:--|#)")
	sqlUnionRegex                  = regexp.MustCompile(`(?i)\bunion(?:\s+(?:all\s+)?select\b|(?:\s+all)?\s*\(\s*select\b)`)
	sqlFunctionRegex               = regexp.MustCompile(`(?i)\b(?:benchmark|pg_sleep|load_file|xp_cmdshell|extractvalue|updatexml)\s*\(|\bwaitfor\s+delay\b|\binto\s+outfile\b|\binformation_schema\b`)
	sqlSleepRegex                  = regexp.MustCompile(`(?i)\bsleep\s*\(`)
	sqlConditionalRegex            = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*(?:or|and|xor|\\|\\||&&)\\s*\\(*\\s*(?:case\\s+when\\b|if\\s*\\()")
	sqlHavingRegex                 = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*having\\s+\\(*\\s*(?:\\d+|'[^']*'|\"[^\"]*\")\\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\\s*(?:\\d+|'[^']*'|\"[^\"]*\")")
	sqlFlexibleBooleanRegex        = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?(?:['"` + "`" + `)]|` + sqlScalarOperand + `)\s*(?:or|and|xor|\|\||&&)\s*(?:not\s*)?(?:true\b|false\b|` + sqlScalarOperand + `\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\s*` + sqlScalarOperand + `|\(*\s*(?:case\s+when\b|if\s*\())`)
	sqlFlexibleHavingRegex         = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?` + sqlScalarOperand + `\s*having\s*` + sqlScalarOperand + `\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\s*` + sqlScalarOperand)
	sqlHexComparisonRegex          = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?0x[0-9a-f]+\s*(?:=|<>|!=|>=|<=|>|<)\s*0x[0-9a-f]+`)
	sqlStackedRegex                = regexp.MustCompile(`(?i);\s*(?:select|insert|update|delete|drop|alter|create|exec|execute)\b`)
	sqlStructuredStackedRegex      = regexp.MustCompile(`(?i);\s*(?:select\b.{0,512}\bfrom\b|insert\s+into\b|update\s+[^\s;]{1,128}\s+set\b|delete\s+from\b|(?:drop|alter|create)\s+(?:table|database|schema|index|view|user|procedure|function)\b|(?:exec|execute)\s+(?:xp_cmdshell|sp_executesql)\b)`)
	sqlVersionCommentRegex         = regexp.MustCompile(`(?is)/\*!\d{0,6}\s*(.*?)\*/`)
	sqlBlockCommentRegex           = regexp.MustCompile(`(?s)/\*.*?\*/`)
	xmlExternalEntityRegex         = regexp.MustCompile(`(?is)<!entity\s+(?:%\s*)?[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlExternalDoctypeRegex        = regexp.MustCompile(`(?is)<!doctype\s+[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlIncludeRegex                = regexp.MustCompile(`(?is)<(?:xi:include|xinclude)\b[^>]{0,512}\bhref\s*=\s*["'](?:file|https?)://`)
	xmlEntityDeclaration           = regexp.MustCompile(`(?is)<!entity\s+(%\s*)?([a-z_][a-z0-9_:.-]*)\s+(?:"([^"]*)"|'([^']*)')\s*>`)
	xmlEntityReference             = regexp.MustCompile(`(?i)([&%])([a-z_][a-z0-9_:.-]*);`)
	commandAmbiguousSeparatorRegex = regexp.MustCompile("(?i)(?:;|&[\\t ]*)[\\t ]*[({]*[\\t ]*(?:sudo[\\t ]+)?[\"']?(?:/(?:[a-z0-9_.?*-]{1,64}/){0,4})?\\b(?:id|env|ls)(?:\\.exe)?(?:[\\t ]|$|[;&|)#'\"$(`<>])")
	commandExplicitSeparatorRegex  = regexp.MustCompile("(?i)(?:;|&[\\t ]*)[\\t ]*[({]*[\\t ]*(?:sudo[\\t ]+)?[\"']?(?:/(?:[a-z0-9_.?*-]{1,64}/){0,4})?\\b" + commandExplicitBinaryGroup + "(?:\\.exe)?(?:[\\t ]|$|[;&|)#'\"$(`<>])")
	commandStrongSeparatorRegex    = regexp.MustCompile("(?i)(?:\\|\\||&&|\\||[\\r\\n])[\\t ]*[({]*[\\t ]*(?:sudo[\\t ]+)?[\"']?(?:/(?:[a-z0-9_.?*-]{1,64}/){0,4})?\\b" + commandAllBinaryGroup + "(?:\\.exe)?(?:[\\t ]|$|[;&|)#'\"$(`<>])")
	commandSubstitutionRegex       = regexp.MustCompile(`(?s)(?:^|[=;,&|:\[])[\t ]*["']?(?:\$\([^\r\n)]{1,512}\)|` + "`" + `[^\r\n` + "`" + `]{1,512}` + "`" + `)`)
	commandAssignmentRegex         = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:cmd|command|exec|execute|shell)["']?\s*(?:=|:)\s*["']?(?:/usr/bin/|/bin/)?` + commandAllBinaryGroup + `(?:\.exe)?\b`)
	commandGenericAssignmentRegex  = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?[a-z_][a-z0-9_.-]{0,63}["']?\s*(?:=|:)\s*["']?(?:/usr/bin/|/bin/)?` + commandGenericBinaryGroup + `(?:\.exe)?\b`)
	commandEnvironmentRegex        = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])\s*(?:[a-z_][a-z0-9_]*=[^\s;&|]{1,256}\s+)+(?:sudo\s+)?(?:/usr/bin/|/bin/)?` + commandAllBinaryGroup + `(?:\.exe)?(?:[\s;&|)#'"$(` + "`" + `<>]|$)`)
	commandWildcardRegex           = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])\s*(?:/[^\s;&|]{0,64})?(?:[a-z0-9_*-]*[?*][a-z0-9_?*-]*)(?:\.exe)?(?:[\s;&|)#'"$(` + "`" + `<>]|$)`)
	commandShellStructureRegex     = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])\s*(?:\(|\{|if\b|then\b|while\b|until\b|for\b|do\b|eval\b)`)
	ssrfHighAssignmentRegex        = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:[a-z0-9_-]*(?:url\d*|uri\d*|link)[a-z0-9_-]*|redirect|next|target|dest|destination|callback|continue|return|endpoint|proxy|fetch|webhook|remote)["']?\s*(?:=|:)\s*["']?([^"'&,\s}]+)`)
	ssrfMediumAssignmentRegex      = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:host|src|image|img|feed|u|site|load|ref|goto|r|open)["']?\s*(?:=|:)\s*["']?([^"'&,\s}]+)`)
	localFileRegex                 = regexp.MustCompile(`(?i)(?:(?:^|[/\\])(?:etc[/\\](?:passwd|shadow|hosts|sudoers|group)|proc[/\\](?:self|\d+)[/\\](?:environ|cmdline|maps)|var[/\\]log[/\\](?:auth\.log|secure)|root[/\\](?:\.ssh[/\\]|\.bash_history)|windows[/\\](?:win\.ini|system32(?:[/\\]|$))|winnt[/\\]win\.ini|\.aws[/\\]credentials|\.env(?:$|[/?#])|[^/\\]*(?:id_rsa|web\.config|wp-config\.php)(?:$|[/?#]))|[a-z]:\\(?:windows\\(?:win\.ini|system32(?:\\|$))|boot\.ini)|(?:php|file|zip|phar|expect|input|glob|ssh2)://)`)
	fileAssignmentRegex            = regexp.MustCompile(`(?i)(?:^|[?&;,\s])(?:file|page|include|template|path|document|folder|root)(?:\[[a-z0-9_-]*\])?\s*=\s*["']?([^"'&,\s}]+)`)
	fileJSONAssignmentRegex        = regexp.MustCompile(`(?i)["'](?:file|page|include|template|path|document|folder|root)["']\s*:\s*["']([^"']+)`)
	xssActiveTagRegex              = regexp.MustCompile(`(?is)<\s*/?\s*(?:script|iframe|object|embed|applet)\b`)
	xssAmbiguousTagRegex           = regexp.MustCompile(`(?is)<\s*/?\s*(?:svg|math|img|video|audio|link|meta|style|base|form|frame|frameset|details|template|isindex)\b`)
	xssEventHandlerRegex           = regexp.MustCompile(`(?i)(?:^|[\t\n\f\r /<"'=])(?:onerror|onload|onclick|onmouseover|onfocus|onblur|onsubmit|oninput|onchange|onanimationstart|ontoggle|onpointerover|onmouseenter|onmouseleave|onmessage|onhashchange)\s*=`)
	xssTagEventHandlerRegex        = regexp.MustCompile(`(?is)<[^<>]{0,1000}[\t\n\f\r /]on[a-z][a-z0-9_-]*\s*=`)
	xssSVGAnimationHandlerRegex    = regexp.MustCompile(`(?is)<\s*(?:set|animate)\b[^<>]{0,1000}\battributename\s*=\s*["']?on[a-z][a-z0-9_-]*["']?[^<>]{0,1000}\bto\s*=`)
	xssJavaScriptURIRegex          = regexp.MustCompile(`(?i)\bjavascript\s*:`)
	xssVBScriptURIRegex            = regexp.MustCompile(`(?i)\bvbscript\s*:`)
	xssDataURIPrefixRegex          = regexp.MustCompile(`(?i)\bdata:`)
	jndiLookupRegex                = regexp.MustCompile(`(?i)\$\{\s*jndi\s*:`)
	jndiExpandedLookupRegex        = regexp.MustCompile(`(?i)\bjndi\s*:`)
	jndiCaseLookupRegex            = regexp.MustCompile(`(?i)\$\{\s*(?:lower|upper)\s*:\s*([^{}]{1,64}?)\s*}`)
	jndiDefaultLookupRegex         = regexp.MustCompile(`(?i)\$\{\s*(?:::\s*|[a-z_][a-z0-9_.-]{0,32}\s*:\s*)-\s*([^{}]{1,64}?)\s*}`)
	jndiEnvironmentDefaultRegex    = regexp.MustCompile(`(?i)\$\{\s*env\s*:[^{}:]{1,128}:-\s*([^{}]{1,64}?)\s*}`)
	detectionRuneReplacer          = strings.NewReplacer(
		"／", "/", "∕", "/", "⁄", "/",
		"＼", `\`, "﹨", `\`,
		"．", ".", "｡", ".", "。", ".", "․", ".",
		"０", "0", "１", "1", "２", "2", "３", "3", "４", "4",
		"５", "5", "６", "6", "７", "7", "８", "8", "９", "9",
	)
	legacyUTF8SeparatorReplacer = strings.NewReplacer(
		"\xc0\xae", ".", "\xc0\xaf", "/", "\xc1\x9c", `\`,
		"\xe0\x80\xae", ".", "\xe0\x80\xaf", "/", "\xe0\x81\x9c", `\`,
		"\xf0\x80\x80\xae", ".", "\xf0\x80\x80\xaf", "/", "\xf0\x80\x81\x9c", `\`,
	)
	urlIgnoredControlReplacer = strings.NewReplacer("\t", "", "\n", "", "\r", "")
	inspectedHeaderNames      = [...]string{
		"Authorization",
		"Content-Type",
		"Cookie",
		"Forwarded",
		"Referer",
		"User-Agent",
		"X-Forwarded-Host",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Host",
		"True-Client-IP",
		"X-Original-URL",
		"X-Rewrite-URL",
	}
)
