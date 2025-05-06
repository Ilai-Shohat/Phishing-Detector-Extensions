import { Severity } from '.';

/** Content-specific error codes */
export enum ContentErrorCode {
    FORM_SUBMISSION = 'FORM_SUBMISSION',
    HIDDEN_INPUTS = 'HIDDEN_INPUTS',
    SUSPICIOUS_IFRAME = 'SUSPICIOUS_IFRAME',
    SUSPICIOUS_LINK = 'SUSPICIOUS_LINK',
    NO_THREAT = 'NO_THREAT',
}

/** Configuration constants for content analysis */
export const CONTENT_CONFIG = {
    MAX_HIDDEN_INPUTS: 3,
    IPV4_PATTERN: /^\d{1,3}(?:\.\d{1,3}){3}$/,
} as const;

/** Non-HTTP protocols used for obfuscation or XSS */
export const SUSPICIOUS_PROTOCOLS = new Set([
    'javascript:',
    'data:',
    'about:',
]) as ReadonlySet<string>;

/** Human-readable messages keyed by code */
export const CONTENT_ERROR_MESSAGES: Record<ContentErrorCode, string> = {
    [ContentErrorCode.FORM_SUBMISSION]: 'Form submission to suspicious URL detected',
    [ContentErrorCode.HIDDEN_INPUTS]: 'Excessive number of hidden inputs detected',
    [ContentErrorCode.SUSPICIOUS_IFRAME]: 'Suspicious iframe source detected',
    [ContentErrorCode.SUSPICIOUS_LINK]: 'Suspicious link detected',
    [ContentErrorCode.NO_THREAT]: 'No suspicious content patterns detected',
};

/** Severity mapping keyed by the same codes */
export const CONTENT_SEVERITY_MAP: Record<ContentErrorCode, Severity> = {
    [ContentErrorCode.FORM_SUBMISSION]: 'high',
    [ContentErrorCode.HIDDEN_INPUTS]: 'medium',
    [ContentErrorCode.SUSPICIOUS_IFRAME]: 'medium',
    [ContentErrorCode.SUSPICIOUS_LINK]: 'low',
    [ContentErrorCode.NO_THREAT]: 'low',
};
