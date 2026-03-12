/**
 * PIIRedactor.js - The Mask
 * 
 * Responsible for finding and redacting Personally Identifiable Information (PII)
 * specifically Emails and URLs, to prevent AI agents from acting on them.
 */

export class PIIRedactor {
    constructor() {
        // Regex for Email Pattern (Simple but effective for capture)
        this.emailRegex = /[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}/yg;

        // Regex for URL Pattern
        this.urlRegex = /https?:\/\/[^\s]+/g;

        // Canary Tracking
        this.canaryMap = new Map(); // Real -> Canary
    }

    /**
     * Generates a synthetic canary address for a given real address.
     * This provides forensic traceability.
     */
    _getCanary(realAddress) {
        if (this.canaryMap.has(realAddress)) {
            return this.canaryMap.get(realAddress);
        }

        const prefix = realAddress.split('@')[0].substring(0, 5);
        const randomHex = Math.random().toString(16).substring(2, 8);
        const canary = `canary-${prefix}-${randomHex}@surgical-guard.audit`;
        
        this.canaryMap.set(realAddress, canary);
        return canary;
    }

    /**
     * Redacts emails and URLs from the text, except for the safe list.
     * @param {string} text - The input text to sanitize.
     * @param {Array<string>} [safeList=[]] - List of strings (emails) to keep unmasked.
     * @param {boolean} [useHoneypot=false] - If true, replaces with a canary instead of a block.
     * @returns {string} - The sanitized text.
     */
    redact(text, safeList = [], useHoneypot = false) {
        if (!text) return text;

        let redactedText = text;

        // 1. Redact Emails
        redactedText = redactedText.replace(this.emailRegex, (match) => {
            // Check if match is in safeList (case-insensitive)
            if (safeList.some(safe => safe.toLowerCase() === match.toLowerCase())) {
                return match;
            }

            if (useHoneypot) {
                const canary = this._getCanary(match);
                console.log(`PIIRedactor: Replaced ${match} with Canary ${canary}`);
                return canary;
            }

            return '[UNVERIFIED_SENDER_REDACTED]';
        });

        // 2. Redact URLs
        redactedText = redactedText.replace(this.urlRegex, (match) => {
            if (useHoneypot) {
                return `https://safe.surgical-guard.audit/verify?target=${btoa(match)}`;
            }
            return '[PROTECTED_URL]';
        });

        return redactedText;
    }
}
