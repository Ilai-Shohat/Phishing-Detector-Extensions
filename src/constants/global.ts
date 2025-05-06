/**
 * Global types and constants shared across the extension
 */

/** Title of the extension */
export const TITLE = "Phishing Detector";

/** Valid detection methods */
export const VALID_METHODS = ['url', 'content', 'behavior', 'unknown'] as const;

/** Detection method type */
export type DetectionMethod = typeof VALID_METHODS[number];

/** Severity levels */
export type Severity = 'low' | 'medium' | 'high';

/** 
 * Maps severity levels to numeric scores (0-1)
 * Used to quantify threat levels for analysis and aggregation
 */
export const SEVERITY_TO_SCORE: Readonly<Record<Severity, number>> = {
    low: 0.3,
    medium: 0.6,
    high: 1.0
} as const;

/** 
 * Thresholds for classifying aggregate risk scores into severity levels
 * Used when combining multiple detection results
 */
export const AGGREGATE_THRESHOLDS = {
    MEDIUM: 0.5,  // Scores above this are considered medium severity
    HIGH: 0.8     // Scores above this are considered high severity
} as const;

/**
 * Result of a phishing detection check
 * Core type used across all detection modules
 */
export interface DetectionResult {
    /** Whether a threat was detected */
    isThreat: boolean;
    /** The detection method used */
    method: DetectionMethod;
    /** Description of the detected threat */
    details: string[];
    /** Severity of the detected threat */
    severity: Severity;
    /** Numeric score between 0 and 1, computed from severity */
    score: number;
    /** Additional metadata about the detection */
    meta?: Record<string, unknown>;
}

/** 
 * Message types for extension communication
 * Used for internal messaging between components
 */
export const MESSAGE_TYPES = {
    GET_LAST_RESULT: 'GET_LAST_RESULT',
    SCAN_REQUEST: 'SCAN_REQUEST'
} as const;

/** 
 * Extension-wide configuration settings (non-URL-specific)
 * Controls various aspects of detection and UI behavior
 */
export const CONFIG = {
    /** Delay between scans (ms) */
    SCAN_DELAY_MS: 1000,
    /** Popup window dimensions */
    POPUP_WIDTH: 300,
    POPUP_HEIGHT: 400,
    /** Maximum number of hidden inputs allowed on page */
    MAX_HIDDEN_INPUTS: 3
} as const;

/** 
 * CSS class names for status indicators
 * Used for styling UI elements based on detection state
 */
export const STATUS_CLASSES = {
    SAFE: 'safe',
    THREAT: 'threat',
    LOADING: 'loading'
} as const;

/** 
 * Status messages displayed in the UI
 * User-facing text for various detection states
 */
export const STATUS_MESSAGES = {
    LOADING: 'Analyzing page...',
    NO_RESULT: 'No scan results available',
    SAFE: 'Page is Safe',
    THREAT: 'Threat Detected'
} as const;
