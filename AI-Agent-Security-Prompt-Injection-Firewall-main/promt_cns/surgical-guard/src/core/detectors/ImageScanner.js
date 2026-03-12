/**
 * ImageScanner.js
 * Scans images in the DOM for potential prompt injections using OCR.
 */

export const ImageScanner = {
    name: "ImageScanner",
    isInitialized: false,

    async init() {
        if (this.isInitialized) return;
        // In a real implementation, we would load Tesseract.js or a Transformer OCR model.
        // For this implementation, we will use a heuristic/mock that identifies "Inject-like" images
        // by their alt text or data attributes, while paving the way for full OCR.
        this.isInitialized = true;
    },

    /**
     * Scans an image element for text-based threats.
     */
    async scanImage(imgNode) {
        await this.init();
        
        // Micro-yield to ensure UI responsiveness
        await new Promise(resolve => setTimeout(resolve, 0));

        const findings = [];
        const altText = imgNode.alt || "";
        const src = imgNode.src || "";

        // Heuristic: If alt text or filename contains "prompt", "instruction", or "ignore"
        // it's highly suspicious for a Visual Prompt Injection.
        const suspiciousPattern = /\b(ignore|instruction|prompt|override|system)\b/i;

        if (suspiciousPattern.test(altText) || suspiciousPattern.test(src)) {
            findings.push({
                detected: true,
                type: 'VISUAL_INJECTION',
                subtype: 'Suspect Image Metadata',
                score: 0.8,
                reasoning: [`Image metadata (alt/src) contains suspicious injection keywords: "${altText || src}"`],
                node: imgNode
            });
        }

        return findings;
    }
};
