import { Severity } from '.';

/**
 * Behavior-specific error codes
 */

export interface MonitorState {
    observer: MutationObserver | null;
    originalHref: string | null;
    lastAlertTime: number;
    scriptInjectionCount: number;
    navigationCount: number;
}
export enum BehaviorErrorCode {
    SCRIPT_INJECTION = 'SCRIPT_INJECTION',
    URL_CHANGE = 'URL_CHANGE',
    PAGE_UNLOAD = 'PAGE_UNLOAD',
    INVALID_URL = 'INVALID_URL',
    NO_THREAT = 'NO_THREAT',
}

/**
 * Configuration constants for behavior analysis
 */
export const BEHAVIOR_CONFIG = {
    /** Delay between alerts in milliseconds */
    DEBOUNCE_DELAY: 1000,
} as const;

/**
 * Human-readable messages for each behavior error code
 */
export const BEHAVIOR_ERROR_MESSAGES: Record<BehaviorErrorCode, string> = {
    [BehaviorErrorCode.SCRIPT_INJECTION]: 'Suspicious script insertion detected',
    [BehaviorErrorCode.URL_CHANGE]: 'Suspicious URL change detected',
    [BehaviorErrorCode.PAGE_UNLOAD]: 'Suspicious page unload detected',
    [BehaviorErrorCode.INVALID_URL]: 'Invalid URL detected',
    [BehaviorErrorCode.NO_THREAT]: 'No suspicious behavior detected',
} as const;

/**
 * Severity mapping for each behavior error code
 */
export const BEHAVIOR_SEVERITY_MAP: Record<BehaviorErrorCode, Severity> = {
    [BehaviorErrorCode.SCRIPT_INJECTION]: 'high',
    [BehaviorErrorCode.URL_CHANGE]: 'medium',
    [BehaviorErrorCode.PAGE_UNLOAD]: 'medium',
    [BehaviorErrorCode.INVALID_URL]: 'high',
    [BehaviorErrorCode.NO_THREAT]: 'low',
} as const;
