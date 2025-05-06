/**
 * URL-based phishing detection module
 * Analyzes URLs for suspicious patterns and characteristics
 * This module is designed to run in content scripts and does not use any Chrome APIs
 */

import { URL_CONFIG, URL_ERROR_MESSAGES, URL_SEVERITY_MAP, UrlErrorCode, DetectionResult } from '../constants';
import { createDetectionResult } from '../utils/detectionResult';

/**
 * Validates and normalizes URL input
 * @param url - URL string to validate and normalize
 * @returns Normalized URL object if valid, null otherwise
 */
function validateAndNormalizeURL(url: string): URL | null {
    if (typeof url !== 'string' || !url.trim()) {
        return null;
    }

    try {
        return new URL(url.trim().toLowerCase());
    } catch {
        return null;
    }
}

/**
 * Checks if URL uses HTTPS protocol
 * @param url - URL object to check
 * @returns True if URL uses HTTPS, false otherwise
 */
function isSecureProtocol(url: URL): boolean {
    return url.protocol === 'https:';
}

/**
 * Checks if URL appears to be a login page
 * @param url - URL object to check
 * @returns True if URL appears to be a login page, false otherwise
 */
function isLoginPage(url: URL): boolean {
    const path = url.pathname.toLowerCase();
    const search = url.search.toLowerCase();
    return path.includes('login') ||
        path.includes('signin') ||
        path.includes('auth') ||
        path.includes('account') ||
        search.includes('login') ||
        search.includes('signin') ||
        search.includes('auth');
}

/**
 * Calculates the entropy of a string using character frequency
 * @param str - String to calculate entropy for
 * @returns Normalized entropy value between 0 and 1
 */
function calculateEntropy(str: string): number {
    if (!str || str.length < 2) return 0;

    const charCount = new Map<string, number>();
    let entropy = 0;
    const length = str.length;

    if (length < 2) return 0;

    // Count character frequencies
    for (const char of str) {
        charCount.set(char, (charCount.get(char) || 0) + 1);
    }

    // Calculate entropy
    const log2 = Math.log2;
    for (const count of charCount.values()) {
        const probability = count / length;
        entropy -= probability * log2(probability);
    }

    // Normalize entropy to 0-1 range
    return entropy / Math.log2(length || 2);
}

/**
 * Counts special characters in a string
 * @param str - String to count special characters in
 * @returns Number of special characters in the string
 */
function countSpecialChars(str: string): number {
    return (str.match(/[^a-zA-Z0-9.-]/g) || []).length;
}

/**
 * Counts dots in a string
 * @param str - String to count dots in
 * @returns Number of dots in the string
 */
function countDots(str: string): number {
    return (str.match(/\./g) || []).length;
}

/**
 * Detects phishing attempts based on URL analysis
 * Analyzes URL length, suspicious keywords, and entropy
 * @param url - URL string to analyze
 * @returns DetectionResult indicating whether suspicious patterns were found
 */
export function detectByURL(url: string): DetectionResult {
    // Input validation
    const parsedUrl = validateAndNormalizeURL(url);
    if (!parsedUrl) {
        return createDetectionResult({
            isThreat: false,
            method: 'url',
            details: [UrlErrorCode.INVALID_INPUT],
            severityMap: URL_SEVERITY_MAP,
            meta: {
                domainLength: 0,
                specialCharCount: 0,
                dotCount: 0,
                entropy: 0,
                normalizedURL: url,
                normalizedDomain: ''
            }
        });
    }

    const issues: UrlErrorCode[] = [];
    const domain = decodeURIComponent(parsedUrl.hostname);
    const specialChars = countSpecialChars(parsedUrl.pathname);
    const entropy = calculateEntropy(domain.replace(/\./g, ''));
    const dotCount = countDots(domain);

    // Check for insecure login pages
    if (isLoginPage(parsedUrl) && !isSecureProtocol(parsedUrl)) {
        issues.push(UrlErrorCode.INSECURE_LOGIN);
    }

    // Check domain length
    if (domain.length > URL_CONFIG.MAX_DOMAIN_LENGTH) {
        issues.push(UrlErrorCode.LONG_DOMAIN);
    }

    // Check number of subdomains
    if (dotCount > URL_CONFIG.MAX_DOTS) {
        issues.push(UrlErrorCode.EXCESSIVE_SUBDOMAINS);
    }

    // Check for excessive special characters
    if (specialChars > URL_CONFIG.MAX_SPECIAL_CHARS) {
        issues.push(UrlErrorCode.EXCESSIVE_SPECIAL_CHARS);
    }

    // Check domain entropy (randomness)
    if (entropy < URL_CONFIG.MIN_ENTROPY_THRESHOLD) {
        issues.push(UrlErrorCode.LOW_ENTROPY);
    } else if (entropy > URL_CONFIG.MAX_ENTROPY_THRESHOLD) {
        issues.push(UrlErrorCode.HIGH_ENTROPY);
    }

    return createDetectionResult({
        isThreat: issues.length > 0,
        method: 'url',
        details: issues.length > 0 ? issues : [UrlErrorCode.NO_THREAT],
        severityMap: URL_SEVERITY_MAP,
        meta: {
            domainLength: domain.length,
            specialCharCount: specialChars,
            dotCount: dotCount,
            entropy: entropy,
            normalizedURL: parsedUrl.href,
            normalizedDomain: domain
        }
    });
} 