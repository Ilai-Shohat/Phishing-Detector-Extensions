/**
 * Content-based phishing detection module
 * Analyzes DOM elements for suspicious patterns and characteristics
 * Designed to run in content scripts without Chrome-specific APIs
 */

import { createDetectionResult } from '../utils/detectionResult';
import {
    DetectionResult,
    ContentErrorCode,
    CONTENT_CONFIG,
    CONTENT_SEVERITY_MAP,
    SUSPICIOUS_PROTOCOLS
} from '../constants';

/**
 * Determines if a URL is suspicious based on protocol, IP addresses, or domain mismatch
 * @param url - The URL string to evaluate
 * @returns true if the URL is considered suspicious
 */
function isSuspiciousURL(url: string): boolean {
    if (!url) return true;
    try {
        const urlObj = new URL(url);

        // Suspicious protocols (e.g., javascript:, data:)
        if (SUSPICIOUS_PROTOCOLS.has(urlObj.protocol)) {
            return true;
        }

        // IP address hostnames
        if (CONTENT_CONFIG.IPV4_PATTERN.test(urlObj.hostname)) {
            return true;
        }

        // Domain mismatch
        if (urlObj.hostname.toLowerCase() !== window.location.hostname.toLowerCase()) {
            return true;
        }

        return false;
    } catch {
        // Malformed URLs are suspicious by default
        return true;
    }
}

/**
 * Checks document forms for suspicious submission targets
 * @returns true if any form submits to a suspicious URL
 */
function analyzeForms(): boolean {
    return Array.from(document.forms).some(
        form => !!form.action && isSuspiciousURL(form.action)
    );
}

/**
 * Checks for an excessive number of hidden input fields
 * @returns true if hidden inputs exceed threshold
 */
function checkHiddenInputs(): boolean {
    return (
        document.querySelectorAll('input[type="hidden"]').length >
        CONTENT_CONFIG.MAX_HIDDEN_INPUTS
    );
}

/**
 * Checks if any iframe element loads from a suspicious source
 * @returns true if any iframe src is suspicious
 */
function analyzeIframes(): boolean {
    return Array.from(document.getElementsByTagName('iframe')).some(
        iframe => !!iframe.src && isSuspiciousURL(iframe.src)
    );
}

/**
 * Checks if any anchor link points to a suspicious URL
 * @returns true if any link href is suspicious
 */
function analyzeLinks(): boolean {
    return Array.from(document.links).some(
        link => !!link.href && isSuspiciousURL(link.href)
    );
}

/**
 * Main content-based detection function
 * @returns DetectionResult capturing any content-based phishing indicators
 */
export function detectByContent(): DetectionResult {
    const issues: ContentErrorCode[] = [];
    const meta: Record<string, unknown> = {
        formCount: document.forms.length,
        hiddenInputCount: document.querySelectorAll('input[type="hidden"]').length,
        iframeCount: document.getElementsByTagName('iframe').length,
        linkCount: document.links.length
    };

    // Form submission checks
    if (analyzeForms()) {
        issues.push(ContentErrorCode.FORM_SUBMISSION);
        meta.suspiciousForms = Array.from(document.forms)
            .filter(f => !!f.action && isSuspiciousURL(f.action))
            .map(f => f.action);
    }

    // Hidden input checks
    if (checkHiddenInputs()) {
        issues.push(ContentErrorCode.HIDDEN_INPUTS);
    }

    // Iframe checks
    if (analyzeIframes()) {
        issues.push(ContentErrorCode.SUSPICIOUS_IFRAME);
        meta.suspiciousIframes = Array.from(
            document.getElementsByTagName('iframe')
        )
            .filter(i => !!i.src && isSuspiciousURL(i.src))
            .map(i => i.src);
    }

    // Link checks
    if (analyzeLinks()) {
        issues.push(ContentErrorCode.SUSPICIOUS_LINK);
        meta.suspiciousLinks = Array.from(document.links)
            .filter(l => !!l.href && isSuspiciousURL(l.href))
            .map(l => l.href);
    }

    // If no issues found, record NO_THREAT code
    if (issues.length === 0) {
        issues.push(ContentErrorCode.NO_THREAT);
    }

    return createDetectionResult({
        isThreat: issues.some(code => code !== ContentErrorCode.NO_THREAT),
        method: 'content',
        details: issues,
        severityMap: CONTENT_SEVERITY_MAP,
        meta
    });
}
