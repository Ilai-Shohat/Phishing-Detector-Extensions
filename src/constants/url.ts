import { Severity } from '.';

/**
 * URL-specific configuration constants
 */
export const URL_CONFIG = {
    /** URL length limits */
    MIN_URL_LENGTH: 5,
    MAX_URL_LENGTH: 100,

    /** Entropy thresholds */
    MIN_ENTROPY_THRESHOLD: 0.2,
    MAX_ENTROPY_THRESHOLD: 0.7,

    /** Domain heuristics */
    MAX_DOMAIN_LENGTH: 30,
    MAX_DOTS: 3,
    MAX_SPECIAL_CHARS: 4,
} as const;

/**
 * URL-specific error codes
 */
export enum UrlErrorCode {
    INVALID_INPUT = 'INVALID_INPUT',
    INSECURE_LOGIN = 'INSECURE_LOGIN',
    HIGH_ENTROPY = 'HIGH_ENTROPY',
    LOW_ENTROPY = 'LOW_ENTROPY',
    EXCESSIVE_SPECIAL_CHARS = 'EXCESSIVE_SPECIAL_CHARS',
    LONG_DOMAIN = 'LONG_DOMAIN',
    EXCESSIVE_SUBDOMAINS = 'EXCESSIVE_SUBDOMAINS',
    NO_THREAT = 'NO_THREAT',
}

/**
 * Human-readable messages for each URL error code
 */
export const URL_ERROR_MESSAGES: Record<UrlErrorCode, string> = {
    [UrlErrorCode.INVALID_INPUT]: 'Invalid URL input',
    [UrlErrorCode.INSECURE_LOGIN]: 'Using insecure HTTP protocol for login/authentication',
    [UrlErrorCode.HIGH_ENTROPY]: 'Domain has unusually high randomness',
    [UrlErrorCode.LOW_ENTROPY]: 'Domain has unusually low randomness',
    [UrlErrorCode.EXCESSIVE_SPECIAL_CHARS]: 'URL contains excessive special characters',
    [UrlErrorCode.LONG_DOMAIN]: 'Domain name is suspiciously long',
    [UrlErrorCode.EXCESSIVE_SUBDOMAINS]: 'URL contains excessive number of subdomains',
    [UrlErrorCode.NO_THREAT]: 'No suspicious patterns detected in URL',
} as const;

/**
 * Severity level mapping for each URL error code
 */
export const URL_SEVERITY_MAP: Record<UrlErrorCode, Severity> = {
    [UrlErrorCode.INVALID_INPUT]: 'high',
    [UrlErrorCode.INSECURE_LOGIN]: 'high',
    [UrlErrorCode.HIGH_ENTROPY]: 'medium',
    [UrlErrorCode.LOW_ENTROPY]: 'medium',
    [UrlErrorCode.EXCESSIVE_SPECIAL_CHARS]: 'medium',
    [UrlErrorCode.LONG_DOMAIN]: 'low',
    [UrlErrorCode.EXCESSIVE_SUBDOMAINS]: 'low',
    [UrlErrorCode.NO_THREAT]: 'low',
} as const;