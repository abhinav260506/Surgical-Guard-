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
     * Active Transmutation (I2D): Rewrites a command into a passive description.
     */
    transmute(text) {
        if (!text) return "A neutral content block.";

        // Mapping common injection patterns to passive descriptions
        if (text.toLowerCase().includes('ignore') || text.toLowerCase().includes('instruction')) {
            return "[ ℹ️ System Advisory: This text contains a request to modify or ignore previous AI instructions. ]";
        }
        if (text.toLowerCase().includes('send') || text.toLowerCase().includes('forward') || text.toLowerCase().includes('email')) {
            return "[ ℹ️ System Advisory: This text contains a request to transmit or forward data to an external address. ]";
        }
        if (text.toLowerCase().includes('transfer') || text.toLowerCase().includes('money') || text.toLowerCase().includes('bank')) {
            return "[ ℹ️ System Advisory: This text contains a request related to financial transactions or bank transfers. ]";
        }
        if (text.toLowerCase().includes('delete') || text.toLowerCase().includes('wipe')) {
            return "[ ℹ️ System Advisory: This text contains a request to delete or remove data. ]";
        }

        return "[ ℹ️ System Advisory: This content was flagged as a potential directive and has been converted into a non-executable fact. ]";
    },

    /**
     * Sanitizes a specific DOM Range (Surgical)
     * AGGRESSIVE Update: Checks attributes and nukes risky elements.
     */
    sanitizeRange(range, findingTypeOrObject) {
        try {
            // 1. Get current content
            const originalText = range.toString();

            // 2. Perform Transmutation (I2D)
            const transmutedText = this.transmute(originalText);

            // 3. Prepare Hover Info
            let titleText = "Surgical-Guard has transmuted this content for your protection.";

            if (typeof findingTypeOrObject === 'object') {
                const finding = findingTypeOrObject;
                if (finding.type === 'ROLE_CONFLICT') {
                    titleText = `Semantic Conflict: ${finding.subtype} detected.`;
                } else if (finding.type === 'MALICIOUS_DIRECTIVE') {
                    titleText = `Directive Removed: ${finding.subtype} found.`;
                }
            }

            // 4. Update DOM
            document.documentElement.setAttribute('data-surgical-tainted', 'true');

            // Create a wrapper
            const span = document.createElement('span');
            span.style.color = '#2563eb'; // Blue for informational
            span.style.backgroundColor = '#eff6ff';
            span.style.borderBottom = '1px dashed #3b82f6';
            span.style.fontWeight = '500';
            span.style.padding = '0 4px';
            span.style.fontStyle = 'italic';
            span.title = titleText;
            span.setAttribute('data-surgical-sanitized', 'true');
            span.setAttribute('data-threat-id', btoa(originalText.length + '-' + Date.now()));

            // Set content: TRANSMUTED TEXT (Fact, not command)
            span.textContent = transmutedText;

            // Sanitize: Delete content and insert new span
            range.deleteContents();
            range.insertNode(span);

            // 5. ATTRIBUTE SCRUBBING (Using Honeypots)
            const parent = range.commonAncestorContainer.nodeType === 1 ?
                range.commonAncestorContainer :
                range.commonAncestorContainer.parentNode;

            if (parent) {
                const riskyAttrs = ['aria-label', 'title', 'alt', 'placeholder', 'data-content', 'value'];
                riskyAttrs.forEach(attr => {
                    if (parent.hasAttribute(attr)) {
                        const attrVal = parent.getAttribute(attr);
                        // Use honeypot mode for attributes to bait attackers
                        const redactedAttr = this.redactor.redact(attrVal, [], true); 
                        parent.setAttribute(attr, redactedAttr);
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
