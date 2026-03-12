console.log("Surgical-Guard Background Service Worker Loaded");

import { AnalysisEngine } from '../core/AnalysisEngine.js';

// Listen for messages from Content Script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    // HANDLER: Text Analysis
    if (request.type === 'ANALYZE_TEXT') {
        const textAsString = request.payload.text;
        const originUrl = sender.tab ? sender.tab.url : 'unknown';

        console.log(`Background: Analysis requested for ${originUrl} (${textAsString.length} chars)`);

        (async () => {
            try {
                // Perform Analysis (Now Async)
                const findings = await AnalysisEngine.analyze(textAsString);

                // Log if threats found
                if (findings.length > 0) {
                    console.warn(`Background: Detected ${findings.length} threats in content from ${originUrl}`);
                } else {
                    console.log("Background: Clean content.");
                }

                // Return results
                sendResponse({
                    status: 'SUCCESS',
                    findings: findings
                });

            } catch (error) {
                console.error("Background: Analysis failed", error);
                sendResponse({
                    status: 'ERROR',
                    message: error.message
                });
            }
        })();

        return true; // Keep channel open for async response
    }

    // HANDLER: Threat Logging
    if (request.type === 'THREATS_DETECTED') {
        const { count, matches, context } = request.payload;

        console.log(`Background: Logging ${count} threats from "${context.title}"`);

        // Update Badge
        chrome.action.setBadgeText({ text: '!' });
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });

        // --- CROSS-TAB CORRELATION LOGIC ---
        chrome.storage.local.get(['globalThreatState', 'activityLog'], (result) => {
            const state = result.globalThreatState || {};
            const logs = result.activityLog || [];

            // Add this tab's primary threat type to global state
            const primaryThreat = matches[0].type;
            const tabId = sender.tab ? sender.tab.id : 'unknown';
            state[tabId] = { type: primaryThreat, url: context.url, timestamp: Date.now() };

            // Check for correlation (e.g., Tab A has 'Instruction Override' and Tab B has 'Data Exfiltration')
            const uniqueThreats = new Set(Object.values(state).map(s => s.type));
            if (uniqueThreats.has('MALICIOUS_DIRECTIVE') && uniqueThreats.size > 1) {
                console.warn("🚨 CROSS-TAB CORRELATION: Multiple threat fragments detected across sessions!");
                // Alert the user via a synthetic high-risk log
                logs.unshift({
                    id: 'correlation-' + Date.now(),
                    timestamp: new Date().toISOString(),
                    title: "CRITICAL: Cross-Tab Attack Correlated",
                    url: "Shared Browser Context",
                    threatCount: uniqueThreats.size,
                    threatType: 'CROSS_TAB_CORRELATION',
                    details: `Fragmented attack patterns detected across ${Object.keys(state).length} tabs.`
                });
            }

            const newEntry = {
                id: Date.now().toString(),
                timestamp: context.timestamp,
                title: context.title,
                url: context.url,
                threatCount: count,
                threatType: primaryThreat,
                details: matches.map(m => m.subtype || m.type).join(', ')
            };

            const updatedLogs = [newEntry, ...logs].slice(0, 100);

            chrome.storage.local.set({ 
                activityLog: updatedLogs,
                globalThreatState: state 
            }, () => {
                console.log("Background: Threat logged and correlated.");
            });
        });

        return false;
    }
});
