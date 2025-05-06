import { Severity } from './global';

/**
 * Configuration constants for content analysis
 */
export const CONTENT_CONFIG = {
    /** Maximum number of hidden inputs before triggering an alert */
    MAX_HIDDEN_INPUTS: 3,
    /** Regular expression to match standard IPv4 addresses */
    IPv4_PATTERN: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
} as const;

/**
 * Set of non-HTTP protocols typically used for obfuscation or XSS vectors
 */
export const SUSPICIOUS_PROTOCOLS = new Set([
    'javascript:',
    'data:',
    'about:'
]) as ReadonlySet<string>;

/**
 * Standardized error messages for content analysis
 */
export const CONTENT_ERROR_MESSAGES = {
    FORM_SUBMISSION: 'Form submission to suspicious URL detected',
    HIDDEN_INPUTS: 'Excessive number of hidden inputs detected',
    SUSPICIOUS_IFRAME: 'Suspicious iframe source detected',
    SUSPICIOUS_LINK: 'Suspicious link detected',
    NO_THREAT: 'No suspicious content patterns detected'
} as const;

/** Severity mapping for content analysis errors */
export const CONTENT_SEVERITY_MAP: Record<keyof typeof CONTENT_ERROR_MESSAGES, Severity> = {
    FORM_SUBMISSION: 'high',
    HIDDEN_INPUTS: 'medium',
    SUSPICIOUS_IFRAME: 'medium',
    SUSPICIOUS_LINK: 'low',
    NO_THREAT: 'low'
} as const; 