document.addEventListener('DOMContentLoaded', function() {
    const API_ENDPOINT = '/api/dashboard-data';
    const FETCH_INTERVAL = 3000; // Fetch data every 3 seconds

    const logCountDisplay = document.getElementById('log-count-display');
    const attackLogBody = document.getElementById('attack-log-body');
    const topIpsBody = document.getElementById('top-ips-body');
    const topUasBody = document.getElementById('top-uas-body');
    const keywordsList = document.getElementById('keywords-list');
    const ipOriginsList = document.getElementById('ip-origins-list');

    // Helper to safely update table body content
    function updateTableBody(tbodyElement, rowsHtml) {
        // Clear existing rows more efficiently than innerHTML = ''
        while (tbodyElement.firstChild) {
            tbodyElement.removeChild(tbodyElement.firstChild);
        }
        // Use a DocumentFragment for better performance when adding rows
        const fragment = document.createDocumentFragment();
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = `<table><tbody>${rowsHtml}</tbody></table>`; // Wrap in table/tbody to parse <tr>
        Array.from(tempDiv.querySelector('tbody').children).forEach(row => {
            fragment.appendChild(row);
        });
        tbodyElement.appendChild(fragment);
    }
    
    // Helper to safely update list content
    function updateList(ulElement, itemsHtml) {
        while (ulElement.firstChild) {
            ulElement.removeChild(ulElement.firstChild);
        }
        const fragment = document.createDocumentFragment();
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = `<ul>${itemsHtml}</ul>`; // Wrap in ul to parse <li>
        Array.from(tempDiv.querySelector('ul').children).forEach(item => {
            fragment.appendChild(item);
        });
        ulElement.appendChild(fragment);
    }

    // Sanitize text content to prevent XSS
    function sanitize(text) {
        const temp = document.createElement('div');
        temp.textContent = text;
        return temp.innerHTML;
    }

    async function fetchData() {
        try {
            const response = await fetch(API_ENDPOINT);
            if (!response.ok) {
                console.error('Failed to fetch dashboard data:', response.status, response.statusText);
                // Display an error message on the dashboard
                return;
            }
            const data = await response.json();
            updateDashboard(data);
        } catch (error) {
            console.error('Error fetching or processing dashboard data:', error);
        }
    }

    function updateDashboard(logs) {
        if (!Array.isArray(logs)) {
            console.error("Received non-array data for logs:", logs);
            return;
        }

        // Update log count display
        if (logCountDisplay) {
            logCountDisplay.textContent = logs.length;
        }

        // Populate Recent Activity Log
        if (attackLogBody) {
            let logHtml = '';
            logs.slice(0, 50).forEach(log => { // Display max 50 recent logs
                logHtml += `
                    <tr>
                        <td>${sanitize(new Date(log.timestamp).toLocaleString())}</td>
                        <td>${sanitize(log.ip)}</td>
                        <td>${sanitize(log.userAgent)}</td>
                        <td>${sanitize(log.path)}</td>
                        <td>${sanitize(log.attackType)}</td>
                        <td>${sanitize(log.details)}<br><small><em>Query: ${sanitize(log.rawQuery)}</em></small><br><small><em>Body: ${sanitize(log.bodySnippet)}</em></small></td>
                    </tr>
                `;
            });
            updateTableBody(attackLogBody, logHtml);
        }
        
        // Aggregate data for Top IPs, UAs, Keywords
        const ipCounts = {};
        const uaCounts = {};
        const keywordCounts = {};

        logs.forEach(log => {
            ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1;
            uaCounts[log.userAgent] = (uaCounts[log.userAgent] || 0) + 1;

            // Extract keywords from details, query, and body snippet
            const textToAnalyze = `${log.details} ${log.rawQuery} ${log.bodySnippet}`;
            const words = textToAnalyze.toLowerCase().match(/\b[a-z0-9]{3,}\b/g) || []; // Basic word extraction
            // Filter out common words or numbers if desired
            const commonWords = new Set(['the', 'and', 'for', 'com', 'http', 'https', 'www', 'api', 'xml', 'version', 'true', 'false', 'null', 'content', 'type', 'user', 'admin', 'select', 'from', 'where']);
            words.forEach(word => {
                if (!commonWords.has(word) && isNaN(word)) { // Avoid pure numbers and common words
                    keywordCounts[word] = (keywordCounts[word] || 0) + 1;
                }
            });
        });

        // Populate Top Attacking IPs
        if (topIpsBody) {
            populateTopTable(topIpsBody, ipCounts, 10);
        }
        if (ipOriginsList) { // Also use ipCounts for the map list
            populateIpOriginsList(ipOriginsList, ipCounts, 10);
        }


        // Populate Top User Agents
        if (topUasBody) {
            populateTopTable(topUasBody, uaCounts, 10);
        }

        // Populate Common Payload Keywords
        if (keywordsList) {
            const sortedKeywords = Object.entries(keywordCounts)
                .sort(([,a],[,b]) => b - a)
                .slice(0, 15); // Top 15 keywords
            let keywordsHtml = '';
            sortedKeywords.forEach(([keyword, count]) => {
                keywordsHtml += `<li>${sanitize(keyword)} (${count})</li>`;
            });
            updateList(keywordsList, keywordsHtml);
        }
    }

    function populateTopTable(tbodyElement, counts, limit) {
        const sortedEntries = Object.entries(counts)
            .sort(([,a],[,b]) => b - a)
            .slice(0, limit);
        
        let tableHtml = '';
        sortedEntries.forEach(([key, count]) => {
            tableHtml += `<tr><td>${sanitize(key)}</td><td>${count}</td></tr>`;
        });
        updateTableBody(tbodyElement, tableHtml);
    }
    
    function populateIpOriginsList(ulElement, ipCounts, limit) {
        const sortedEntries = Object.entries(ipCounts)
            .sort(([,a],[,b]) => b - a)
            .slice(0, limit); // Top N IPs
        let listHtml = '';
        sortedEntries.forEach(([ip, count]) => {
            // Placeholder for actual geolocation. For now, just list IP and count
            listHtml += `<li>${sanitize(ip)} (Count: ${count}) - Origin: Unknown (Placeholder)</li>`;
        });
        updateList(ulElement, listHtml);
    }


    // Initial fetch and set interval for updates
    fetchData();
    setInterval(fetchData, FETCH_INTERVAL);
});