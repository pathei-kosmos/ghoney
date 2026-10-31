package main

import (
	"regexp"
	"strings"
)

const (
	// Keep command groups together for every shell context
	commandAmbiguousBinaryNames = `id|env|ls|go|strings|timeout`
	commandCoreBinaryNames      = `whoami|hostname|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|printenv|sleep|python|python3|perl|ruby|busybox`
	commandExtendedBinaryNames  = `echo|rm|cp|mv|touch|mkdir|chmod|chown|cut|head|tail|grep|awk|sed|dd|find|xargs|tee|ps|ifconfig|ss|nmap|git|ssh|scp|socat|openssl|tar|fdisk|iptables|systemctl|crontab|useradd|ncat|telnet|ftp|rsync|nohup|strace|gdb|xxd|gcc|node|php|java|docker|kubectl|ipconfig|certutil|wmic|bitsadmin|mshta|rundll32|regsvr32|cscript|net|sc|type|dir`
	commandExplicitBinaryGroup  = `(?:` + commandCoreBinaryNames + `|` + commandExtendedBinaryNames + `)`
	commandAllBinaryGroup       = `(?:` + commandAmbiguousBinaryNames + `|base64|` + commandCoreBinaryNames + `|` + commandExtendedBinaryNames + `)`
	commandGenericBinaryGroup   = `(?:whoami|uname|ipconfig|certutil|wmic|bitsadmin|mshta|rundll32|regsvr32|cscript)`
	localPathSeparator          = `(?:[/\\]+(?:\.[/\\]+)*)`
	// Keep SQL operands bounded so flexible conditional signatures remain linear
	sqlScalarOperand = `(?:\(*\s*(?:0x[0-9a-f]+|[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[-+]?\d+)?|'[^']{0,128}'|"[^"]{0,128}"|char\s*\(\s*(?:\d+\s*,\s*){0,15}\d+\s*\)|true|false)\s*\)*)`
	// Accept a bounded two-level SQL function expression without recursive parsing
	sqlFunctionOperand = `(?:[a-z_][a-z0-9_]{0,63}\s*\(\s*(?:(?:[^()\r\n]{0,128})|(?:[a-z_][a-z0-9_]{0,63}\s*\([^()\r\n]{0,128}\))){0,4}\s*\))`
)

var (
	// Compile signatures once at startup
	noSQLJSONKeyRegex              = regexp.MustCompile(`"(?:[^"\\]|\\.)*"\s*:`)
	pathTraversalRegex             = regexp.MustCompile(`(?:\.{2,}[/\\]|\.\.;[/\\])`)
	sqlQuotedBooleanRegex          = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*(?:or|and|xor|\\|\\||&&)\\s*(?:not\\s+)?(?:\\d+|'[^']*'|\"[^\"]*\")\\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\\s*(?:\\d+|'[^']*'|\"[^\"]*\")")
	sqlTruncatedQuotedBooleanRegex = regexp.MustCompile("(?i)(?:'|\")\\)?\\s*(?:or|and|xor|\\|\\||&&)\\s*\\(?\\s*(?:'[^']{0,128}'|\"[^\"]{0,128}\")\\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\\s*(?:'[^']{0,128}|\"[^\"]{0,128})")
	sqlParenthesizedQuotedRegex    = regexp.MustCompile(`(?i)['"]\s*(?:or|and|xor)\s*\(\s*['"][^)]{1,128}\)\s*(?:=|<>|!=|>=|<=|>|<)\s*['"][^&;,\s}]{1,128}`)
	sqlNumericBooleanRegex         = regexp.MustCompile(`(?i)(?:^|[?&;\s])(?:[a-z_][a-z0-9_.-]*=)?\d+\s+(?:or|and|xor|\|\||&&)\s+\d+\s*(?:=|<>|!=|>=|<=|>|<)\s*\d+`)
	sqlCommentTailRegex            = regexp.MustCompile("(?i)(?:'|\"|`)\\s*(?:--|#)")
	sqlUnionRegex                  = regexp.MustCompile(`(?i)\bunion(?:\s+(?:all\s+)?select\b|(?:\s+all)?\s*\(\s*select\b)`)
	sqlFunctionRegex               = regexp.MustCompile(`(?i)\b(?:benchmark|pg_sleep|load_file|xp_cmdshell|extractvalue|updatexml)\s*\(|\bwaitfor\s+delay\b|\binto\s+outfile\b|\binformation_schema\s*\.`)
	sqlSleepRegex                  = regexp.MustCompile(`(?i)(?:^|[?&;,{]|\b(?:and|or)\s+)\s*(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?sleep\s*\(`)
	sqlConditionalRegex            = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*(?:or|and|xor|\\|\\||&&)\\s*\\(*\\s*(?:case\\s+when\\b|if\\s*\\()")
	sqlHavingRegex                 = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*having\\s+\\(*\\s*(?:\\d+|'[^']*'|\"[^\"]*\")\\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\\s*(?:\\d+|'[^']*'|\"[^\"]*\")")
	sqlFlexibleBooleanRegex        = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?(?:['"` + "`" + `)]|` + sqlScalarOperand + `)\s*(?:or|and|xor|\|\||&&)\s*(?:not\s*)?(?:true\b|false\b|` + sqlScalarOperand + `\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\s*` + sqlScalarOperand + `|\(*\s*(?:case\s+when\b|if\s*\())`)
	sqlFlexibleHavingRegex         = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?` + sqlScalarOperand + `\s*having\s*` + sqlScalarOperand + `\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\s*` + sqlScalarOperand)
	sqlHexComparisonRegex          = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?0x[0-9a-f]+\s*(?:=|<>|!=|>=|<=|>|<)\s*0x[0-9a-f]+`)
	sqlBareBooleanRegex            = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])[a-z_][a-z0-9_.-]{0,63}\s*=\s*(?:0x[0-9a-f]+|[-+]?\d+(?:\.\d+)?(?:e[-+]?\d+)?|['"][^'"&;,]{0,128}['"]?|true|false)\s+(?:or|and|xor|\|\||&&)\s+(?:0x[0-9a-f]+|[-+]?\d+(?:\.\d+)?(?:e[-+]?\d+)?|['"][^'"&;,]{1,128}['"]?|true|false)(?:\s|$|[&#,;}])`)
	sqlPredicateRegex              = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?(?:` + sqlScalarOperand + `|['"])(?:\s+|\s*\)\s*)(?:or|and|xor)\s+(?:` + sqlScalarOperand + `\s+(?:between\s+` + sqlScalarOperand + `\s+and\s+` + sqlScalarOperand + `|in\s*\(\s*[^()\r\n]{1,256}\s*\)|is\s+(?:not\s+)?null\b)|exists\s*\(\s*select\b)`)
	sqlFunctionComparisonRegex     = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?(?:` + sqlScalarOperand + `|['"])\s*(?:or|and|xor)\s+` + sqlFunctionOperand + `\s*(?:=|<>|!=|>=|<=|>|<|like|regexp)\s*(?:` + sqlScalarOperand + `|` + sqlFunctionOperand + `)`)
	sqlReconnaissanceRegex         = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?(?:` + sqlScalarOperand + `|['"])\s+(?:(?:order|group)\s+by\s+\d+(?:\s*,\s*\d+)*|limit\s+\d+(?:\s+offset\s+\d+)?|procedure\s+analyse\s*\(\s*\)|for\s+update\b)`)
	sqlBooleanExpressionRegex      = regexp.MustCompile(`(?i)(?:^|[?&;,\s:="'{\[])(?:[a-z_][a-z0-9_.-]{0,63}\s*=\s*)?(?:` + sqlScalarOperand + `|['"])\s+(?:and|or|xor)\s+(?:\(\s*select\b|(?:sleep|database|user|version|current_user)\s*\(|(?:current_user|@@version)\b)`)

	sqlStackedRegex             = regexp.MustCompile(`(?i);\s*(?:select|insert|update|delete|drop|alter|create|exec|execute)\b`)
	sqlStructuredStackedRegex   = regexp.MustCompile(`(?i);\s*(?:select\b.{0,512}\bfrom\b|insert\s+into\b|update\s+[^\s;]{1,128}\s+set\b|delete\s+from\b|(?:drop|alter|create)\s+(?:table|database|schema|index|view|user|procedure|function)\b|(?:exec|execute)\s+(?:xp_cmdshell|sp_executesql)\b)`)
	sqlVersionCommentRegex      = regexp.MustCompile(`(?is)/\*!\d{0,6}\s*(.*?)\*/`)
	sqlBlockCommentRegex        = regexp.MustCompile(`(?s)/\*.*?\*/`)
	xmlExternalEntityRegex      = regexp.MustCompile(`(?is)<!entity\s+(?:%\s*)?[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlExternalDoctypeRegex     = regexp.MustCompile(`(?is)<!doctype\s+[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlIncludeRegex             = regexp.MustCompile(`(?is)<(?:xi:include|xinclude)\b[^>]{0,512}\bhref\s*=\s*["'](?:file|https?)://`)
	xmlEntityDeclaration        = regexp.MustCompile(`(?is)<!entity\s+(%\s*)?([a-z_][a-z0-9_:.-]*)\s+(?:"([^"]*)"|'([^']*)')\s*>`)
	xmlEntityReference          = regexp.MustCompile(`(?i)([&%])([a-z_][a-z0-9_:.-]*);`)
	commandShellVariableRegex   = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])[\t ]*(?:\$shell|\$\{shell})[\t ]+-c\b`)
	commandExecutablePathRegex  = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])[\t ]*/(?:[a-z0-9_.-]{1,64}/){0,8}[a-z0-9_.-]{1,64}(?:[\t ]|$|[;&|)])`)
	commandBase64SeparatorRegex = regexp.MustCompile(`(?i)(?:;|&)[\t ]*(?:/usr/bin/|/bin/)?base64(?:[\t ]|$|[&|)])`)

	commandAmbiguousSeparatorRegex = regexp.MustCompile("(?i)(?:;|&)[\\t ]*[({]*(?:sudo[\\t ]+)?[\"']?(?:/(?:[a-z0-9_.?*-]{1,64}/){0,4})?\\b(?:" + commandAmbiguousBinaryNames + ")(?:\\.exe)?(?:[\\t ]|$|[;&|)#'\"$(`<>])")
	commandExplicitSeparatorRegex  = regexp.MustCompile("(?i)(?:;|&[\\t ]*)[\\t ]*[({]*[\\t ]*(?:sudo[\\t ]+)?[\"']?(?:/(?:[a-z0-9_.?*-]{1,64}/){0,4})?\\b" + commandExplicitBinaryGroup + "(?:\\.exe)?(?:[\\t ]|$|[;&|)#'\"$(`<>])")
	commandStrongSeparatorRegex    = regexp.MustCompile("(?i)(?:\\|\\||&&|\\||[\\r\\n])[\\t ]*[({]*[\\t ]*(?:sudo[\\t ]+)?[\"']?(?:/(?:[a-z0-9_.?*-]{1,64}/){0,4})?\\b" + commandAllBinaryGroup + "(?:\\.exe)?(?:[\\t ]|$|[;&|)#'\"$(`<>])")
	commandSubstitutionRegex       = regexp.MustCompile(`(?s)(?:^|[=;,&|:\[])[\t ]*["']?(?:\$\([^\r\n)]{1,512}\)|` + "`" + `[^\r\n` + "`" + `]{1,512}` + "`" + `)`)
	commandAssignmentRegex         = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:cmd|command|exec|execute|shell)["']?\s*(?:=|:)\s*["']?(?:/usr/bin/|/bin/)?` + commandAllBinaryGroup + `(?:\.exe)?(?:[\s;&|)#'"$(` + "`" + `<>]|$)`)
	commandGenericAssignmentRegex  = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?[a-z_][a-z0-9_.-]{0,63}["']?\s*(?:=|:)\s*["']?(?:/usr/bin/|/bin/)?` + commandGenericBinaryGroup + `(?:\.exe)?\b`)
	commandEnvironmentRegex        = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])\s*(?:[a-z_][a-z0-9_]*=[^\s;&|]{1,256}\s+)+(?:sudo\s+)?(?:/usr/bin/|/bin/)?` + commandAllBinaryGroup + `(?:\.exe)?(?:[\s;&|)#'"$(` + "`" + `<>]|$)`)
	commandWildcardRegex           = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])\s*(?:/[^\s;&|]{0,64})?(?:[a-z0-9_*-]*[?*][a-z0-9_?*-]*)(?:\.exe)?(?:[\s;&|)#'"$(` + "`" + `<>]|$)`)
	commandShellStructureRegex     = regexp.MustCompile(`(?i)(?:;|&&|\||[\r\n])\s*(?:\(|\{|if\b|then\b|while\b|until\b|for\b|do\b|eval\b)`)
	shellEmptyExpansionRegex       = regexp.MustCompile(`([a-z])(?:\$@|\$\*|\$\(\))([a-z])`)
	shellDefaultExpansionRegex     = regexp.MustCompile(`\$\{[a-z_][a-z0-9_]{0,63}:-([^{}]{0,64})}`)

	ssrfShortParameterRegex   = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?[ur]["']?\s*(?:=|:)`)
	ssrfHighAssignmentRegex   = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:[a-z0-9_-]*(?:url\d*|uri\d*|link)[a-z0-9_-]*|redirect|next|target|dest|destination|callback|continue|return|endpoint|proxy|fetch|webhook|remote)["']?\s*(?:=|:)\s*["']?([^"'&,\s}]+)`)
	ssrfMediumAssignmentRegex = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:host|src|image|img|feed|u|site|load|ref|goto|r|open)["']?\s*(?:=|:)\s*["']?([^"'&,\s}]+)`)
	directURLTargetRegex      = regexp.MustCompile(`(?i)((?:jar:)?(?:https?|ftp|tftp|gopher|dict|ldap|ssh|wss?)://[^\s"'&,}<]+)`)
	remoteFileURLRegex        = regexp.MustCompile(`(?i)((?:https?|ftp|tftp)://[^\s"'&,}<]+\.(?:php\d*|phtml|phar|inc|txt|conf|config|jsp|aspx?|cgi)(?:[?#][^\s"'&,}<]*)?)`)
	localFileRegex            = regexp.MustCompile(`(?i)(?:(?:^|[/\\])(?:etc` + localPathSeparator + `(?:passwd|shadow|hosts|sudoers|group)|proc` + localPathSeparator + `(?:self|\d+)` + localPathSeparator + `(?:environ|cmdline|maps|status)|var` + localPathSeparator + `log` + localPathSeparator + `(?:auth\.log|secure)|root` + localPathSeparator + `(?:\.ssh` + localPathSeparator + `|\.bash_history)|windows` + localPathSeparator + `(?:win\.ini|system32(?:[/\\]|$))|winnt` + localPathSeparator + `win\.ini|\.aws` + localPathSeparator + `credentials|\.env(?:$|[/?#])|[^/\\]*(?:id_rsa|web\.config|wp-config\.php)(?:$|[/?#]))|[a-z]:[/\\](?:windows\\(?:win\.ini|system32(?:\\|$))|boot\.ini)|(?:^|[=:\s"'])(?:\.env|\.git[/\\]config|\.svn[/\\]entries)(?:$|[/?#&"'])|(?:php|file|zip|phar|expect|input|glob|ssh2)://)`)
	fileAssignmentRegex       = regexp.MustCompile(`(?i)(?:^|[?&;,\s])(?:file|page|include|template|path|document|folder|root)(?:\[[a-z0-9_-]*\])?\s*=\s*["']?([^"'&,\s}]+)`)
	fileJSONAssignmentRegex   = regexp.MustCompile(`(?i)["'](?:file|page|include|template|path|document|folder|root)["']\s*:\s*["']([^"']+)`)
	xssActiveTagRegex         = regexp.MustCompile(`(?is)<\s*/?\s*(?:script|iframe|object|embed|applet)\b`)
	xssAmbiguousTagRegex      = regexp.MustCompile(`(?is)<\s*/?\s*(?:svg|math|img|video|audio|link|meta|style|base|form|frame|frameset|details|template|isindex)\b`)
	xssEventHandlerRegex      = regexp.MustCompile(`(?i)(?:^|[\t\n\f\r /<"'=])(?:onerror|onload|onclick|onmouseover|onfocus|onblur|onsubmit|oninput|onchange|onanimationstart|ontoggle|onpointerover|onmouseenter|onmouseleave|onmessage|onhashchange)\s*=`)
	xssAnyEventHandlerRegex   = regexp.MustCompile(`(?i)[\t\n\f\r /]on[a-z][a-z0-9_-]*\s*=`)

	xssTagEventHandlerRegex     = regexp.MustCompile(`(?is)<[^<>]*[\t\n\f\r /]on[a-z][a-z0-9_-]*\s*=`)
	xssSVGAnimationHandlerRegex = regexp.MustCompile(`(?is)<\s*(?:set|animate)\b[^<>]{0,1000}\battributename\s*=\s*["']?on[a-z][a-z0-9_-]*["']?[^<>]{0,1000}\bto\s*=`)
	xssJavaScriptURIRegex       = regexp.MustCompile(`(?i)\bjavascript\s*:`)
	xssVBScriptURIRegex         = regexp.MustCompile(`(?i)\bvbscript\s*:`)
	xssDataURIPrefixRegex       = regexp.MustCompile(`(?i)\bdata:`)
	jndiLookupRegex             = regexp.MustCompile(`(?i)\$\{\s*jndi\s*:`)
	jndiExpandedLookupRegex     = regexp.MustCompile(`(?i)\bjndi\s*:`)
	jndiProtocolRegex           = regexp.MustCompile(`(?i)\bjndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https|nis|nds|corba)\s*:`)
	jndiCaseLookupRegex         = regexp.MustCompile(`(?i)\$\{\s*(?:lower|upper)\s*:\s*([^{}]{1,64}?)\s*}`)
	jndiDefaultLookupRegex      = regexp.MustCompile(`(?i)\$\{\s*(?:::\s*|[a-z_][a-z0-9_.-]{0,32}\s*:\s*)-\s*([^{}]{1,64}?)\s*}`)
	jndiEnvironmentDefaultRegex = regexp.MustCompile(`(?i)\$\{\s*env\s*:[^{}:]{1,128}:-\s*([^{}]{1,64}?)\s*}`)
	detectionRuneReplacer       = strings.NewReplacer(
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
)
