/**
 * SanitizationEngine
 * Responsible for "I2D Transmutation" - converting Malicious Instructions into Informational Descriptions.
 */

import { PIIRedactor } from './PIIRedactor.js';

export const Sanitizer = {
    redactor: new PIIRedactor(),

    /**
     * Neutralizes detected threats in a text block.
     * @param {string} text - The original text
     * @param {Array} findings - Array of scanning findings (from DirectiveScanner)
     * @returns {string} - The sanitized text
     */
    sanitizeText(text, findings) {
        // We only sanitize segments that have malicious directives, avoiding blanket PII redaction.
        let sanitizedText = text;

        findings.forEach(finding => {
            if (finding.type === 'MALICIOUS_DIRECTIVE') {
                const warningMsg = ` [🚫 BLOCKED: Unauthorized Command (${finding.subtype}) ] `;
                if (sanitizedText.includes(finding.match)) {
                    sanitizedText = sanitizedText.replace(finding.match, `${warningMsg}`);
                }
            }
            else if (finding.type === 'ROLE_CONFLICT') {
                const warningMsg = ` [🚫 BLOCKED: Context Hijacking (${finding.context}) ] `;
                if (sanitizedText.includes(finding.match)) {
                    sanitizedText = sanitizedText.replace(finding.match, `${warningMsg}`);
                }
            }
        });

        // Gap 1: Fragmentation guard — reconstruct and re-check for semantic anomalies
        const fragments = text.split(/[\n\r]+/).join(' ');
        if (this._containsSuspiciousIntent(fragments) && findings.length === 0) {
            sanitizedText = ` [🚫 BLOCKED: Semantic anomaly detected — content pattern matches known injection structure] `;
        }

        return sanitizedText;
    },

    /**
     * Gap 1 Helper: Checks for high-level suspicious intent across fragments.
     */
    _containsSuspiciousIntent(text) {
        const semanticFlags = [
            /\b(ignore|disregard|forget).{0,30}(above|previous|prior|instructions?)\b/i,
            /\b(you are now|act as|pretend|your new (role|task|directive))\b/i,
            /\b(send|forward|exfiltrate).{0,40}(to|at)\s+\S+@\S+\.\S+/i,
        ];
        return semanticFlags.some(r => r.test(text));
    },

    /**
     * Gap 4: Validates page content against the user's stated session intent.
     */
    validateAgainstIntent(pageText, userIntent) {
        if (!userIntent) return { safe: true };

        const actionWords = pageText.match(
            /\b(send|forward|delete|download|submit|click|navigate|reply)\b/gi
        ) || [];

        const suspiciousActions = actionWords.filter(a =>
            !userIntent.toLowerCase().includes(a.toLowerCase())
        );

        if (suspiciousActions.length > 2) {
            return {
                safe: false,
                reason: `Page contains ${suspiciousActions.length} action directives outside stated intent`,
                actions: [...new Set(suspiciousActions)]
            };
        }
        return { safe: true };
    },

    /**
     * Sanitizes a specific DOM Range (Surgical)
     * AGGRESSIVE Update: Checks attributes and nukes risky elements.
     */
    sanitizeRange(range, findingTypeOrObject) {
        try {
            // Step C: DOM Replacement (The "Firewall")

            // 1. Get current content
            const originalText = range.toString();

            // Previously: Step B: Entity Redaction was applied unconditionally.
            // Now: Redaction is only needed if building a custom string or replacement.
            // But since the *entire malicious range* gets replaced with a warning, redaction of original
            // text inside it is unnecessary (it goes away entirely).
            const redactedText = originalText;

            // 3. Prepare Warning
            let warningText = " [ 🚫 Dangerous Directive Neutralized ] ";
            let titleText = "Surgical-Guard has neutralized this content.";

            if (typeof findingTypeOrObject === 'object') {
                const finding = findingTypeOrObject;
                if (finding.type === 'ROLE_CONFLICT') {
                    warningText = ` [ 🚫 Blocked: ${finding.subtype} ] `;
                    titleText = `Semantic Analysis Result: ${finding.reasoning ? finding.reasoning[0] : 'Role Conflict'}`;
                } else if (finding.type === 'MALICIOUS_DIRECTIVE') {
                    warningText = ` [ 🚫 Command Removed: ${finding.subtype} ] `;
                }
            }

            // 4. Update DOM
            // Gap 2: Set page-level taint flag
            document.documentElement.setAttribute('data-surgical-tainted', 'true');
            if (typeof findingTypeOrObject === 'object' && findingTypeOrObject.severity) {
                document.documentElement.setAttribute('data-taint-level', findingTypeOrObject.severity);
            }

            // Create a wrapper
            const span = document.createElement('span');
            span.style.color = '#dc2626';
            span.style.backgroundColor = '#fee2e2';
            span.style.borderBottom = '1px dashed #ef4444';
            span.style.fontWeight = '600';
            span.style.padding = '0 4px';
            span.title = titleText;
            span.setAttribute('data-surgical-sanitized', 'true');

            // Gap 2: Replace malicious text with a non-invertible fingerprint only
            span.setAttribute('data-threat-id', btoa(originalText.length + '-' + Date.now()));

            // Set content: STRICT BLOCKING (Removed originalText to prevent AI scraping from data layers)
            span.textContent = `${warningText}`;

            // Sanitize: Delete content and insert new span
            range.deleteContents();
            range.insertNode(span);

            // 5. ATTRIBUTE SCRUBBING
            const parent = range.commonAncestorContainer.nodeType === 1 ?
                range.commonAncestorContainer :
                range.commonAncestorContainer.parentNode;

            if (parent) {
                const riskyAttrs = ['aria-label', 'title', 'alt', 'placeholder', 'data-content', 'value'];
                riskyAttrs.forEach(attr => {
                    if (parent.hasAttribute(attr)) {
                        // Redact attributes too!
                        const attrVal = parent.getAttribute(attr);
                        const redactedAttr = this.redactor.redact(attrVal);
                        if (redactedAttr !== attrVal) {
                            parent.setAttribute(attr, redactedAttr);
                            console.log(`Surgical-Guard: Redacted PII in attribute '${attr}'.`);
                        } else {
                            // If no PII but malicious, scrub
                            parent.removeAttribute(attr);
                        }
                    }
                });
            }

            return true;
        } catch (e) {
            console.warn("Surgical-Guard: Failed to sanitize range", e);
            return false;
        }
    },


    /**
     * Neutralizes a DOM node by replacing it with a warning banner or safe text.
     * @param {Node} node - The DOM node to sanitize
     * @param {Object} finding - The finding object (e.g. Hidden Text)
     */
    sanitizeNode(node, finding) {
        if (finding.type === 'HIDDEN_TEXT') {
            const originalText = node.textContent;

            // Gap 2: Taint the document
            document.documentElement.setAttribute('data-surgical-tainted', 'true');

            // Overwrite node content — removing original text from DOM
            node.textContent = `[ 🚫 Hidden Prompt Injection Neutralized ]`;

            // Hash the original length/timestamp for tracking
            node.setAttribute('data-threat-id', btoa(originalText.length + '-' + Date.now()));

            node.style.display = 'block';
            node.style.visibility = 'visible';
            node.style.opacity = '1';
            node.style.fontSize = '12px';
            node.style.color = 'red';
            node.style.backgroundColor = '#ffe6e6';
            node.style.border = '1px solid red';
            node.style.position = 'static';

            node.setAttribute('data-surgical-scanned', 'true');
            node.classList.add('surgical-guard-warning');

            // Scrub attributes here too
            ['aria-label', 'title', 'alt'].forEach(attr => node.removeAttribute(attr));
        }
    }
};
