document.addEventListener('DOMContentLoaded', () => {
    const API_ENDPOINT = '/api/dashboard-data';
    const FETCH_INTERVAL_MS = 3000;
    const FETCH_TIMEOUT_MS = 5000;
    const elements = {
        count: document.getElementById('log-count-display'),
        status: document.getElementById('connection-status'),
        activity: document.getElementById('attack-log-body'),
        topIps: document.getElementById('top-ips-body'),
        topUas: document.getElementById('top-uas-body'),
        attackTypes: document.getElementById('attack-types-body'),
        keywords: document.getElementById('keywords-list')
    };
    let fetchInProgress = false;

    // Drop existing nodes without parsing HTML
    function clear(element) {
        element.replaceChildren();
    }

    // Build cells from text nodes only
    function textCell(value) {
        const cell = document.createElement('td');
        cell.textContent = String(value ?? '');
        return cell;
    }

    // Render payload details without creating markup
    function detailCell(log) {
        const cell = document.createElement('td');
        const summary = document.createElement('div');
        summary.textContent = String(log.details ?? '');
        cell.appendChild(summary);

        [['Query', log.rawQuery], ['Body', log.bodySnippet]].forEach(([label, value]) => {
            const line = document.createElement('small');
            const emphasis = document.createElement('em');
            emphasis.textContent = `${label}: ${String(value ?? '')}`;
            line.appendChild(emphasis);
            cell.appendChild(line);
        });
        return cell;
    }

    // Render the newest events first
    function renderActivity(logs) {
        clear(elements.activity);
        if (logs.length === 0) {
            const row = document.createElement('tr');
            const cell = textCell('No events detected yet.');
            cell.colSpan = 6;
            cell.className = 'empty-state';
            row.appendChild(cell);
            elements.activity.appendChild(row);
            return;
        }

        const fragment = document.createDocumentFragment();
        logs.slice(0, 50).forEach((log) => {
            const row = document.createElement('tr');
            row.append(
                textCell(new Date(log.timestamp).toLocaleString()),
                textCell(log.ip),
                textCell(log.userAgent),
                textCell(log.path),
                textCell(log.attackType),
                detailCell(log)
            );
            fragment.appendChild(row);
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

    // Render a compact frequency table
    function renderCountTable(element, entries, limit = 10) {
        clear(element);
        if (entries.length === 0) {
            const row = document.createElement('tr');
            const cell = textCell('No data yet.');
            cell.colSpan = 2;
            cell.className = 'empty-state';
            row.appendChild(cell);
            element.appendChild(row);
            return;
        }
        const fragment = document.createDocumentFragment();
        entries.slice(0, limit).forEach(([value, count]) => {
            const row = document.createElement('tr');
            row.append(textCell(value), textCell(count));
            fragment.appendChild(row);
        });
        element.appendChild(fragment);
    }

    // Extract a small vocabulary from captured payloads
    function extractKeywords(logs) {
        const ignored = new Set([
            'the', 'and', 'for', 'com', 'http', 'https', 'www', 'api', 'xml',
            'true', 'false', 'null', 'content', 'type', 'user', 'admin',
            'select', 'from', 'where', 'detected', 'pattern'
        ]);
        const counts = new Map();
        logs.forEach((log) => {
            const text = `${log.details ?? ''} ${log.rawQuery ?? ''} ${log.bodySnippet ?? ''}`;
            const words = text.toLowerCase().match(/\b[a-z0-9]{3,}\b/g) || [];
            words.forEach((word) => {
                if (!ignored.has(word) && Number.isNaN(Number(word))) {
                    counts.set(word, (counts.get(word) || 0) + 1);
                }
            });
        });
        return [...counts.entries()].sort((left, right) => right[1] - left[1]);
    }

    // Render keywords through textContent
    function renderKeywords(entries) {
        clear(elements.keywords);
        if (entries.length === 0) {
            const item = document.createElement('li');
            item.className = 'empty-state';
            item.textContent = 'No data yet.';
            elements.keywords.appendChild(item);
            return;
        }
        const fragment = document.createDocumentFragment();
        entries.slice(0, 15).forEach(([keyword, count]) => {
            const item = document.createElement('li');
            item.textContent = `${keyword} (${count})`;
            fragment.appendChild(item);
        });
        elements.keywords.appendChild(fragment);
    }

    // Refresh every panel from one API snapshot
    function renderDashboard(logs) {
        elements.count.textContent = String(logs.length);
        renderActivity(logs);
        renderCountTable(elements.topIps, countBy(logs, 'ip'));
        renderCountTable(elements.topUas, countBy(logs, 'userAgent'));
        renderCountTable(elements.attackTypes, countBy(logs, 'attackType'));
        renderKeywords(extractKeywords(logs));
    }

    // Surface polling failures without clearing existing data
    function setConnectionStatus(message, failed = false) {
        elements.status.textContent = message;
        elements.status.classList.toggle('status-error', failed);
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
            renderDashboard(logs);
            setConnectionStatus(`Live · ${new Date().toLocaleTimeString()}`);
        } catch (error) {
            console.error('Dashboard refresh failed:', error);
            setConnectionStatus('Refresh failed', true);
        } finally {
            window.clearTimeout(timeout);
            fetchInProgress = false;
        }
    }

    // Fetch once now, then poll at a low fixed rate
    fetchData();
    window.setInterval(fetchData, FETCH_INTERVAL_MS);
});
