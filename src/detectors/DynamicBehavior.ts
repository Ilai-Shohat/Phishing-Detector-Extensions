/**
 * Behavior-based phishing detection module
 * Monitors page behavior for suspicious activities using MutationObserver and URL change detection
 */

import { createDetectionResult, levenshteinDistance } from '../utils/detectionResult';
import {
    DetectionResult,
    SUSPICIOUS_PROTOCOLS,
    BehaviorErrorCode,
    BEHAVIOR_CONFIG,
    BEHAVIOR_SEVERITY_MAP,
    MonitorState
} from '../constants';

/**
 * Calculates a threat score based on behavioral factors
 * @param type - Error code to evaluate
 * @param state - Current monitoring state
 * @returns Score between 0 and 1
 */
function calculateThreatScore(
    type: BehaviorErrorCode,
    state: MonitorState
): number {
    let baseScore = 0;
    const timeWeight = Math.min(
        (Date.now() - state.lastAlertTime) / BEHAVIOR_CONFIG.DEBOUNCE_DELAY,
        1
    );

    switch (type) {
        case BehaviorErrorCode.SCRIPT_INJECTION:
            baseScore = 0.7 + state.scriptInjectionCount * 0.1;
            break;
        case BehaviorErrorCode.URL_CHANGE:
            const urlDiff = state.originalHref
                ? levenshteinDistance(state.originalHref, window.location.href) / 100
                : 0;
            baseScore = 0.5 + Math.min(urlDiff, 0.3);
            break;
        case BehaviorErrorCode.PAGE_UNLOAD:
            baseScore = 0.4 + state.navigationCount * 0.05;
            break;
        case BehaviorErrorCode.INVALID_URL:
            baseScore = 0.6;
            break;
        default:
            baseScore = 0.3;
    }
    const finalScore = baseScore * timeWeight;
    return Math.min(Math.max(finalScore, 0), 1);
}

/**
 * Validates URL for suspicious patterns
 */
function isSuspiciousURL(url: string): boolean {
    if (!url) return true;
    try {
        const urlObj = new URL(url);
        const currentUrl = new URL(window.location.href);
        if (SUSPICIOUS_PROTOCOLS.has(urlObj.protocol)) return true;
        return (
            urlObj.hostname.toLowerCase() !==
            currentUrl.hostname.toLowerCase()
        );
    } catch {
        return true;
    }
}

/**
 * Sets up DOM mutation observer to detect script injections
 */
function setupDOMMonitor(
    callback: (res: DetectionResult) => void,
    state: MonitorState
): void {
    state.observer = new MutationObserver(mutations => {
        const now = Date.now();
        if (now - state.lastAlertTime < BEHAVIOR_CONFIG.DEBOUNCE_DELAY) return;
        if (
            mutations.some(m =>
                Array.from(m.addedNodes).some(
                    node => node.nodeName === 'SCRIPT'
                )
            )
        ) {
            state.lastAlertTime = now;
            state.scriptInjectionCount++;
            const score = calculateThreatScore(
                BehaviorErrorCode.SCRIPT_INJECTION,
                state
            );
            callback(
                createDetectionResult({
                    isThreat: true,
                    method: 'behavior',
                    details: [BehaviorErrorCode.SCRIPT_INJECTION],
                    severityMap: BEHAVIOR_SEVERITY_MAP,
                    meta: {
                        scriptInjectionCount: state.scriptInjectionCount,
                        navigationCount: state.navigationCount,
                        threatScore: score
                    }
                })
            );
        }
    });
    state.observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });
}

/**
 * Sets up URL change listeners to detect suspicious navigation
 */
function setupURLMonitor(
    callback: (res: DetectionResult) => void,
    state: MonitorState
): void {
    state.originalHref = window.location.href;
    const handleChange = () => {
        const now = Date.now();
        if (now - state.lastAlertTime < BEHAVIOR_CONFIG.DEBOUNCE_DELAY) return;
        if (isSuspiciousURL(window.location.href)) {
            state.lastAlertTime = now;
            state.navigationCount++;
            const urlDiff = state.originalHref
                ? levenshteinDistance(state.originalHref, window.location.href) / 100
                : 0;
            const score = calculateThreatScore(
                BehaviorErrorCode.URL_CHANGE,
                state
            );
            callback(
                createDetectionResult({
                    isThreat: true,
                    method: 'behavior',
                    details: [BehaviorErrorCode.URL_CHANGE],
                    severityMap: BEHAVIOR_SEVERITY_MAP,
                    meta: {
                        scriptInjectionCount: state.scriptInjectionCount,
                        navigationCount: state.navigationCount,
                        urlDiffScore: urlDiff,
                        threatScore: score
                    }
                })
            );
        }
    };
    window.addEventListener('hashchange', handleChange);
    window.addEventListener('popstate', handleChange);
    window.addEventListener('beforeunload', handleChange);
}

/**
 * Starts behavior monitoring and returns a cleanup function
 */
export function startBehaviorMonitor(
    callback: (res: DetectionResult) => void
): () => void {
    const state: MonitorState = {
        observer: null,
        originalHref: null,
        lastAlertTime: 0,
        scriptInjectionCount: 0,
        navigationCount: 0
    };
    if (state.observer) state.observer.disconnect();
    setupDOMMonitor(callback, state);
    setupURLMonitor(callback, state);
    return () => {
        if (state.observer) {
            state.observer.disconnect();
            state.observer = null;
        }
        state.originalHref = null;
        state.lastAlertTime = 0;
        state.scriptInjectionCount = 0;
        state.navigationCount = 0;
    };
}
