document.addEventListener('DOMContentLoaded', () => {
    const API_ENDPOINT = '/api/dashboard-data';
    const FETCH_INTERVAL_MS = 3000;
    const FETCH_TIMEOUT_MS = 5000;
    const RANK_LIMIT = 6;
    const TOP_IP_LIMIT = 5;
    const ATTACK_TYPE_LIMIT = 9;
    const INDICATOR_LIMIT = 16;
    // Keep payload indicators explicit and locally evaluated
    const PAYLOAD_INDICATORS = [
        { label: '/etc/passwd', pattern: /\/etc\/passwd/i },
        { label: '../', pattern: /\.\.[/\\]/ },
        { label: 'union select', pattern: /\bunion\s+(?:all\s+)?select\b/i },
        { label: 'or 1=1', pattern: /\bor\s+1\s*=\s*1\b/i },
        { label: 'sleep(', pattern: /\bsleep\s*\(/i },
        { label: 'benchmark(', pattern: /\bbenchmark\s*\(/i },
        { label: '<!entity', pattern: /<!entity\b/i },
        { label: 'system', pattern: /\bsystem\s+["']/i },
        { label: 'file://', pattern: /\bfile:\/\//i },
        { label: '169.254.169.254', pattern: /\b169\.254\.169\.254\b/ },
        { label: '127.0.0.1', pattern: /\b127\.0\.0\.1\b/ },
        { label: 'localhost', pattern: /\blocalhost\b/i },
        { label: '<script', pattern: /<script\b/i },
        { label: '<svg', pattern: /<svg\b/i },
        { label: 'onerror=', pattern: /\bonerror\s*=/i },
        { label: 'onload=', pattern: /\bonload\s*=/i },
        { label: 'javascript:', pattern: /\bjavascript\s*:/i },
        { label: 'alert(', pattern: /\balert\s*\(/i },
        { label: '${jndi:', pattern: /\$\{jndi\s*:/i },
        { label: 'ldap:', pattern: /\bldap\s*:/i },
        { label: 'rmi:', pattern: /\brmi\s*:/i },
        { label: '$where', pattern: /\$where\b/i },
        { label: '$function', pattern: /\$function\b/i },
        { label: '$regex', pattern: /\$regex\b/i },
        { label: '$ne', pattern: /\$ne\b/i },
        { label: 'whoami', pattern: /\bwhoami\b/i },
        { label: '/bin/sh', pattern: /\/bin\/sh\b/i },
        { label: '&&', pattern: /&&/ },
        { label: '$(', pattern: /\$\(/ }
    ];
    const elements = {
        count: document.getElementById('log-count-display'),
        uniqueIps: document.getElementById('unique-ip-count'),
        highConfidence: document.getElementById('high-confidence-count'),
        mediumConfidence: document.getElementById('medium-confidence-note'),
        lastActivity: document.getElementById('last-activity'),
        lastSource: document.getElementById('last-source'),
        status: document.getElementById('connection-status'),
        statusLabel: document.getElementById('connection-label'),
        currentTime: document.getElementById('current-time'),
        version: document.getElementById('app-version'),
        activitySummary: document.getElementById('activity-summary'),
        clearFilter: document.getElementById('clear-filter'),
        activity: document.getElementById('attack-log-body'),
        topIps: document.getElementById('top-ips-list'),
        topUas: document.getElementById('top-uas-list'),
        attackTypes: document.getElementById('attack-types-list'),
        keywords: document.getElementById('keywords-list')
    };
    const summaryCards = [...document.querySelectorAll('[data-summary-view]')];
    let fetchInProgress = false;
    let currentLogs = [];
    let activeFilters = new Map();
    let summaryView = 'all';
    const expandedEvents = new Set();

    // Drop existing nodes without parsing HTML
    function clear(element) {
        element.replaceChildren();
    }

    // Keep time labels compact in dense views
    function formatTimestamp(value) {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return 'Unknown';
        }
        return new Intl.DateTimeFormat(undefined, {
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }).format(date);
    }

    // Express recency without implying long-term storage
    function timeAgo(value) {
        const timestamp = new Date(value).getTime();
        if (Number.isNaN(timestamp)) {
            return 'Unknown';
        }
        const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
        if (seconds < 60) {
            return `${seconds}s ago`;
        }
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) {
            return `${minutes}m ago`;
        }
        const hours = Math.floor(minutes / 60);
        if (hours < 24) {
            return `${hours}h ago`;
        }
        return `${Math.floor(hours / 24)}d ago`;
    }

    // Build plain text cells with mobile labels
    function textCell(value, label, className = '') {
        const cell = document.createElement('td');
        cell.dataset.label = label;
        cell.className = className;
        cell.textContent = String(value ?? '');
        return cell;
    }

    // Copy captured text with a fallback for older browsers
    async function copyText(value, button) {
        const originalLabel = button.textContent;
        let helper;
        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(value);
            } else {
                helper = document.createElement('textarea');
                helper.className = 'clipboard-helper';
                helper.value = value;
                helper.readOnly = true;
                document.body.appendChild(helper);
                helper.select();
                if (!document.execCommand('copy')) {
                    throw new Error('Copy command failed');
                }
            }
            button.textContent = 'Copied';
        } catch (error) {
            console.error('Copy failed:', error);
            button.textContent = 'Copy failed';
        } finally {
            helper?.remove();
        }
        window.setTimeout(() => {
            button.textContent = originalLabel;
        }, 1400);
    }

    // Build one copy action without exposing markup
    function copyButton(label, value) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'event-action';
        button.textContent = `Copy ${label}`;
        button.addEventListener('click', () => copyText(String(value), button));
        return button;
    }

    // Build one expanded detail field
    function eventDetail(label, value, span = 1) {
        const field = document.createElement('div');
        field.className = 'event-detail';
        if (span > 1) {
            field.classList.add(`event-detail-span-${span}`);
        }
        const name = document.createElement('span');
        name.className = 'event-detail-label';
        name.textContent = label;
        const content = document.createElement('code');
        content.textContent = String(value);
        field.append(name, content);
        return field;
    }

    // Build a full width detail row below one event
    function eventDetailRow(log, index, isExpanded) {
        const row = document.createElement('tr');
        row.id = `event-details-${index}`;
        row.className = 'event-detail-row';
        row.hidden = !isExpanded;
        const cell = document.createElement('td');
        cell.colSpan = 7;
        const expanded = document.createElement('div');
        expanded.className = 'event-expanded';
        expanded.append(
            eventDetail('IP address', log.ip || 'Unknown'),
            eventDetail('User agent', log.userAgent || 'Unknown'),
            eventDetail('Path', log.path || '/')
        );
        const hasQuery = Boolean(log.rawQuery);
        const hasBody = Boolean(log.bodySnippet);
        if (log.details) {
            expanded.appendChild(eventDetail('Detection', log.details, hasQuery || hasBody ? 1 : 3));
        }
        if (hasQuery) {
            expanded.append(
                eventDetail('Raw query', log.rawQuery),
                eventDetail('Decoded query', decodePayload(log.rawQuery))
            );
        }
        if (hasBody) {
            expanded.appendChild(eventDetail('Body', log.bodySnippet, hasQuery ? 3 : 2));
        }
        cell.appendChild(expanded);
        row.appendChild(cell);
        return row;
    }

    // Render payload context and actions without widening the row
    function detailCell(log, detailRow, key) {
        const cell = document.createElement('td');
        cell.dataset.label = 'Details';
        const detailContent = document.createElement('div');
        detailContent.className = 'event-detail-content';
        const summary = document.createElement('div');
        summary.className = 'detail-summary';
        summary.textContent = String(log.details ?? '');
        detailContent.appendChild(summary);

        [['Query', log.rawQuery], ['Body', log.bodySnippet]].forEach(([label, value]) => {
            if (!value) {
                return;
            }
            const line = document.createElement('div');
            line.className = 'payload-line';
            const name = document.createElement('span');
            name.className = 'payload-label';
            name.textContent = label;
            const payload = document.createElement('span');
            payload.className = 'payload-value';
            payload.textContent = String(value);
            line.append(name, payload);
            detailContent.appendChild(line);
        });

        const actions = document.createElement('div');
        actions.className = 'event-actions';
        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'event-action';
        toggle.textContent = detailRow.hidden ? 'Details' : 'Hide details';
        toggle.setAttribute('aria-expanded', String(!detailRow.hidden));
        toggle.setAttribute('aria-controls', detailRow.id);
        actions.appendChild(toggle);
        if (log.rawQuery) {
            actions.appendChild(copyButton('query', log.rawQuery));
        }
        if (log.bodySnippet) {
            actions.appendChild(copyButton('body', log.bodySnippet));
        }
        const layout = document.createElement('div');
        layout.className = 'event-detail-layout';
        layout.append(detailContent, actions);
        cell.appendChild(layout);

        toggle.addEventListener('click', () => {
            const opening = detailRow.hidden;
            detailRow.hidden = !opening;
            if (opening) {
                expandedEvents.add(key);
            } else {
                expandedEvents.delete(key);
            }
            toggle.textContent = opening ? 'Hide details' : 'Details';
            toggle.setAttribute('aria-expanded', String(opening));
        });
        return cell;
    }

    // Map known families to a fixed visual palette
    function attackTone(value) {
        const tones = {
            'LFI/RFI': 'red',
            'SSRF': 'orange',
            'Command Injection': 'yellow',
            'SQL Injection': 'blue',
            'Path Traversal': 'magenta',
            'XML Entity': 'purple',
            'XSS': 'green',
            'JNDI Injection': 'cyan',
            'NoSQL Injection': 'teal',
            'HoneypotAccess': 'neutral',
            'NotFound': 'neutral'
        };
        return tones[value] || 'neutral';
    }

    // Give attack families a consistent compact label
    function attackTypeCell(value) {
        const labels = {
            'Command Injection': 'Cmd Inj.',
            'SQL Injection': 'SQL Inj.',
            'Path Traversal': 'Path Trav.',
            'JNDI Injection': 'JNDI Inj.',
            'NoSQL Injection': 'NoSQL Inj.',
            'HoneypotAccess': 'Honeypot',
            'NotFound': 'Not Found'
        };
        const cell = document.createElement('td');
        cell.dataset.label = 'Attack type';
        cell.className = 'attack-type-cell';
        const badge = document.createElement('span');
        badge.className = `attack-type-badge attack-tone-${attackTone(value)}`;
        badge.textContent = labels[value] || String(value ?? 'Unknown');
        badge.title = String(value ?? 'Unknown');
        cell.appendChild(badge);
        return cell;
    }

    // Render confidence badges with text nodes
    function confidenceCell(value) {
        const cell = document.createElement('td');
        cell.dataset.label = 'Confidence';
        const badge = document.createElement('span');
        const confidence = value === 'high' || value === 'medium' ? value : 'access';
        badge.className = `confidence-badge confidence-${confidence}`;
        badge.textContent = confidence;
        cell.appendChild(badge);
        return cell;
    }

    // Render the newest events first
    function renderActivity(logs) {
        clear(elements.activity);
        if (logs.length === 0) {
            const row = document.createElement('tr');
            const cell = textCell('No events detected yet', '', 'empty-state');
            cell.colSpan = 7;
            row.appendChild(cell);
            elements.activity.appendChild(row);
            return;
        }

        const fragment = document.createDocumentFragment();
        logs.forEach((log, index) => {
            const row = document.createElement('tr');
            const key = eventKey(log);
            const detailRow = eventDetailRow(log, index, expandedEvents.has(key));
            row.dataset.confidence = log.confidence || 'access';
            row.append(
                textCell(formatTimestamp(log.timestamp), 'Timestamp', 'timestamp'),
                textCell(log.ip, 'IP address', 'ip-value'),
                textCell(log.userAgent, 'User agent', 'user-agent-value'),
                textCell(log.path, 'Path', 'path-value'),
                attackTypeCell(log.attackType),
                confidenceCell(log.confidence),
                detailCell(log, detailRow, key)
            );
            fragment.append(row, detailRow);
        });
        elements.activity.appendChild(fragment);
    }

    // Count and rank one event field
    function countBy(logs, field) {
        const counts = new Map();
        logs.forEach((log) => {
            const key = String(log[field] || 'Unknown');
            counts.set(key, (counts.get(key) || 0) + 1);
        });
        return [...counts.entries()].sort((left, right) => right[1] - left[1]);
    }

    // Decode captured payloads with a fixed pass limit
    function decodePayload(value) {
        let decoded = String(value ?? '').replace(/\+/g, ' ');
        for (let pass = 0; pass < 3; pass += 1) {
            try {
                const next = decodeURIComponent(decoded);
                if (next === decoded) {
                    break;
                }
                decoded = next;
            } catch {
                break;
            }
        }
        return decoded;
    }

    // Keep signal extraction tied to captured input
    function payloadText(log) {
        return `${decodePayload(log.rawQuery)} ${decodePayload(log.bodySnippet)}`;
    }

    // Identify one retained event across polling refreshes
    function eventKey(log) {
        return [
            log.timestamp,
            log.ip,
            log.userAgent,
            log.path,
            log.attackType,
            log.rawQuery,
            log.bodySnippet
        ].map((value) => String(value ?? '')).join('\u001f');
    }

    // Check whether a ranking value is selected
    function filterIsActive(field, value) {
        return activeFilters.get(field)?.has(value) || false;
    }

    // Toggle values independently within each filter category
    function toggleFilter(field, value) {
        const values = new Set(activeFilters.get(field) || []);
        if (values.has(value)) {
            values.delete(value);
        } else {
            values.add(value);
        }
        if (values.size === 0) {
            activeFilters.delete(field);
        } else {
            activeFilters.set(field, values);
        }
        renderDashboard(currentLogs);
    }

    // Count active values across every filter category
    function activeFilterCount() {
        let count = summaryView === 'all' ? 0 : 1;
        activeFilters.forEach((values) => {
            count += values.size;
        });
        return count;
    }

    // Apply OR within categories and AND between categories
    function filterLogs(logs) {
        let filtered = logs.filter((log) => {
            for (const [field, values] of activeFilters) {
                if (field === 'keyword') {
                    if (![...values].some((value) => indicatorMatches(log, value))) {
                        return false;
                    }
                } else if (!values.has(String(log[field] || 'Unknown'))) {
                    return false;
                }
            }
            return true;
        });

        if (summaryView === 'high') {
            filtered = filtered.filter((log) => log.confidence === 'high');
        } else if (summaryView === 'latest') {
            filtered = filtered.slice(0, 1);
        } else if (summaryView === 'unique') {
            const seen = new Set();
            filtered = filtered.filter((log) => {
                const source = String(log.ip || 'Unknown');
                if (seen.has(source)) {
                    return false;
                }
                seen.add(source);
                return true;
            });
        }
        return filtered;
    }

    // Render clickable rankings with native progress bars
    function renderRankedList(element, entries, field, limit = RANK_LIMIT, toneForValue = null) {
        clear(element);
        if (entries.length === 0) {
            const message = document.createElement('p');
            message.className = 'empty-state';
            message.textContent = 'No data yet';
            element.appendChild(message);
            return;
        }

        const maximum = entries[0][1];
        const fragment = document.createDocumentFragment();
        entries.slice(0, limit).forEach(([value, count], index) => {
            const item = document.createElement('button');
            item.type = 'button';
            const tone = toneForValue ? toneForValue(value) : String(index % 6);
            item.className = `rank-item rank-tone-${tone}`;
            const selected = filterIsActive(field, value);
            item.classList.toggle('is-active', selected);
            item.setAttribute('aria-pressed', String(selected));
            item.addEventListener('click', () => toggleFilter(field, value));
            const copy = document.createElement('div');
            copy.className = 'rank-copy';
            const label = document.createElement('span');
            label.className = 'rank-label';
            label.textContent = value;
            label.title = value;
            const total = document.createElement('strong');
            total.className = 'rank-count';
            total.textContent = String(count);
            copy.append(label, total);

            const progress = document.createElement('progress');
            progress.className = 'rank-progress';
            progress.max = maximum;
            progress.value = count;
            progress.setAttribute('aria-label', `${value}: ${count}`);
            item.append(copy, progress);
            fragment.appendChild(item);
        });
        element.appendChild(fragment);
    }

    // Match one known or observed indicator against decoded input
    function indicatorMatches(log, indicator) {
        const payload = payloadText(log).toLowerCase();
        const known = PAYLOAD_INDICATORS.find(({ label }) => label === indicator);
        return known ? known.pattern.test(payload) : payload.includes(indicator);
    }

    // Extract useful indicators without counting repeats inside one event
    function extractKeywords(logs) {
        const ignored = new Set([
            'the', 'and', 'for', 'com', 'http', 'https', 'www', 'api', 'xml',
            'true', 'false', 'null', 'content', 'type', 'user', 'admin',
            'example', 'latest', 'meta', 'data', 'file', 'url', 'guest',
            'name', 'value'
        ]);
        const counts = new Map();
        logs.forEach((log) => {
            const text = payloadText(log);
            const indicators = new Set();
            PAYLOAD_INDICATORS.forEach(({ label, pattern }) => {
                if (pattern.test(text)) {
                    indicators.add(label);
                }
            });
            const coveredWords = new Set(
                [...indicators].flatMap((indicator) => indicator.match(/[a-z]{3,}/g) || [])
            );
            const words = text.toLowerCase().match(/\$[a-z]{2,10}|\b[a-z][a-z0-9]{2,}\b/g) || [];
            new Set(words).forEach((word) => {
                if (!ignored.has(word) && !coveredWords.has(word) && Number.isNaN(Number(word))) {
                    indicators.add(word);
                }
            });
            indicators.forEach((indicator) => {
                counts.set(indicator, (counts.get(indicator) || 0) + 1);
            });
        });
        return [...counts.entries()].sort((left, right) => right[1] - left[1]);
    }

    // Render keyword filters through textContent
    function renderKeywords(entries) {
        clear(elements.keywords);
        if (entries.length === 0) {
            const item = document.createElement('li');
            item.className = 'empty-state';
            item.textContent = 'No data yet';
            elements.keywords.appendChild(item);
            return;
        }
        const fragment = document.createDocumentFragment();
        entries.slice(0, INDICATOR_LIMIT).forEach(([keyword, count]) => {
            const item = document.createElement('li');
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'keyword-chip';
            const selected = filterIsActive('keyword', keyword);
            button.classList.toggle('is-active', selected);
            button.setAttribute('aria-pressed', String(selected));
            button.addEventListener('click', () => toggleFilter('keyword', keyword));
            const label = document.createElement('span');
            label.className = 'keyword-label';
            label.textContent = keyword;
            label.title = keyword;
            const total = document.createElement('span');
            total.className = 'keyword-count';
            total.textContent = String(count);
            button.append(label, total);
            item.appendChild(button);
            fragment.appendChild(item);
        });
        elements.keywords.appendChild(fragment);
    }

    // Refresh every panel from one API snapshot
    function renderDashboard(logs) {
        currentLogs = logs;
        const retainedKeys = new Set(logs.map(eventKey));
        expandedEvents.forEach((key) => {
            if (!retainedKeys.has(key)) {
                expandedEvents.delete(key);
            }
        });
        const highConfidence = logs.filter((log) => log.confidence === 'high').length;
        const mediumConfidence = logs.filter((log) => log.confidence === 'medium').length;
        const detections = logs.filter((log) => log.confidence === 'high' || log.confidence === 'medium');
        const uniqueIps = new Set(logs.map((log) => log.ip).filter(Boolean));
        const newest = logs[0];
        const visibleLogs = filterLogs(logs);
        const filterCount = activeFilterCount();

        elements.count.textContent = String(logs.length);
        elements.uniqueIps.textContent = String(uniqueIps.size);
        elements.highConfidence.textContent = String(highConfidence);
        elements.mediumConfidence.textContent = `${mediumConfidence} medium confidence`;
        elements.lastActivity.textContent = newest ? timeAgo(newest.timestamp) : 'None';
        elements.lastSource.textContent = newest ? `From ${newest.ip || 'unknown source'}` : 'Awaiting traffic';
        elements.clearFilter.hidden = filterCount === 0;
        elements.activitySummary.lastChild.textContent = filterCount > 0
            ? `${visibleLogs.length} of ${logs.length} events · ${filterCount} selected`
            : `${logs.length} events · newest first`;
        summaryCards.forEach((card) => {
            const selected = card.dataset.summaryView === summaryView;
            card.classList.toggle('is-active', selected);
            card.setAttribute('aria-pressed', String(selected));
        });

        renderActivity(visibleLogs);
        renderRankedList(elements.topIps, countBy(logs, 'ip'), 'ip', TOP_IP_LIMIT);
        renderRankedList(elements.topUas, countBy(logs, 'userAgent'), 'userAgent');
        renderRankedList(
            elements.attackTypes,
            countBy(detections, 'attackType'),
            'attackType',
            ATTACK_TYPE_LIMIT,
            attackTone
        );
        renderKeywords(extractKeywords(detections));
    }

    // Surface polling failures without clearing existing data
    function setConnectionStatus(message, failed = false) {
        elements.statusLabel.textContent = message;
        elements.status.classList.toggle('status-error', failed);
    }

    // Keep the header clock independent from API polling
    function updateClock() {
        elements.currentTime.dateTime = new Date().toISOString();
        elements.currentTime.textContent = new Intl.DateTimeFormat(undefined, {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }).format(new Date());
    }

    // Avoid overlapping polls and reject malformed responses
    async function fetchData() {
        if (fetchInProgress) {
            return;
        }
        fetchInProgress = true;
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        try {
            const response = await fetch(API_ENDPOINT, {
                cache: 'no-store',
                signal: controller.signal
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const logs = await response.json();
            if (!Array.isArray(logs)) {
                throw new Error('Unexpected API response');
            }
            elements.version.textContent = response.headers.get('X-Ghoney-Version') || 'dev';
            renderDashboard(logs);
            setConnectionStatus('Live');
        } catch (error) {
            console.error('Dashboard refresh failed:', error);
            setConnectionStatus('Refresh failed', true);
        } finally {
            window.clearTimeout(timeout);
            fetchInProgress = false;
        }
    }

    // Start the clock and telemetry polling
    summaryCards.forEach((card) => {
        card.addEventListener('click', () => {
            const requestedView = card.dataset.summaryView;
            if (requestedView === 'all') {
                summaryView = 'all';
                activeFilters = new Map();
            } else {
                summaryView = summaryView === requestedView ? 'all' : requestedView;
            }
            renderDashboard(currentLogs);
        });
    });
    elements.clearFilter.addEventListener('click', () => {
        summaryView = 'all';
        activeFilters = new Map();
        renderDashboard(currentLogs);
    });
    updateClock();
    window.setInterval(updateClock, 1000);
    fetchData();
    window.setInterval(fetchData, FETCH_INTERVAL_MS);
});
