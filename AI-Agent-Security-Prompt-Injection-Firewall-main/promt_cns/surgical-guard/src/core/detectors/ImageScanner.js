import { createWorker } from 'tesseract.js';

export const ImageScanner = {
    name: "ImageScanner",
    isInitialized: false,
    worker: null,

    async init() {
        if (this.isInitialized) return;
        
        console.log("ImageScanner: Initializing Tesseract.js Worker...");
        try {
            this.worker = await createWorker('eng');
            this.isInitialized = true;
            console.log("ImageScanner: OCR Worker Ready.");
        } catch (e) {
            console.error("ImageScanner: OCR Init failed", e);
        }
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

        // 1. Fast Path: Metadata Check
        const suspiciousPattern = /\b(ignore|instruction|prompt|override|system)\b/i;
        if (suspiciousPattern.test(altText) || suspiciousPattern.test(src)) {
            findings.push({
                detected: true,
                type: 'VISUAL_INJECTION',
                subtype: 'Suspect Image Metadata',
                score: 0.8,
                reasoning: [`Image metadata contains suspicious keywords.`],
                node: imgNode
            });
            return findings;
        }

        // 2. Slow Path: Full OCR
        if (this.isInitialized && src && (src.startsWith('http') || src.startsWith('data:'))) {
            try {
                console.log("ImageScanner: Running OCR on image...");
                const { data: { text } } = await this.worker.recognize(src);
                
                if (text && suspiciousPattern.test(text)) {
                    findings.push({
                        detected: true,
                        type: 'VISUAL_INJECTION',
                        subtype: 'OCR Threat Detection',
                        score: 0.95,
                        reasoning: [`OCR detected suspicious text in image: "${text.substring(0, 50)}..."`],
                        node: imgNode
                    });
                }
            } catch (err) {
                console.warn("ImageScanner: OCR scanning failed for image", src, err);
            }
        }

        return findings;
    }
};
