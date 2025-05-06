// detectionUtils.ts
import {
    DetectionResult,
    Severity,
    DetectionMethod,
    SEVERITY_TO_SCORE,
    VALID_METHODS,
} from '../constants';

/**
 * Gets the maximum severity from a list of error codes using a severity map
 * @param details - Array of error codes (e.g. UrlErrorCode)
 * @param severityMap - Map of those codes to severity levels
 * @returns Highest severity level found
 */
export function getMaxSeverity<C extends string>(
    details: C[],
    severityMap: Record<C, Severity>
): Severity {
    return details.reduce((max: Severity, code) => {
        const current = severityMap[code];
        return SEVERITY_TO_SCORE[current] > SEVERITY_TO_SCORE[max] ? current : max;
    }, 'low');
}

/**
 * Type guard to validate if an object is a valid DetectionResult
 * @param obj - Object to validate
 * @returns true if obj is a valid DetectionResult
 */
export function isDetectionResult(obj: unknown): obj is DetectionResult {
    if (!obj || typeof obj !== 'object') return false;
    const r = obj as DetectionResult;
    return (
        typeof r.isThreat === 'boolean' &&
        typeof r.method === 'string' &&
        VALID_METHODS.includes(r.method as DetectionMethod) &&
        Array.isArray(r.details) &&
        ['low', 'medium', 'high'].includes(r.severity) &&
        typeof r.score === 'number' &&
        r.score >= 0 &&
        r.score <= 1
    );
}

/**
 * Creates a standardized detection result with computed severity and score
 * @param params - Parameters for creating the detection result
 * @throws Error if method is not a valid DetectionMethod
 * @returns Fully formed DetectionResult object
 */
export function createDetectionResult<C extends string>(params: {
    isThreat: boolean;
    method: DetectionMethod;
    details: C[];
    severityMap: Record<C, Severity>;
    meta?: Record<string, unknown>;
}): DetectionResult {
    const { isThreat, method, details, severityMap, meta } = params;

    if (!VALID_METHODS.includes(method)) {
        throw new Error(
            `Invalid detection method: ${method}. Must be one of: ${VALID_METHODS.join(', ')}`
        );
    }

    // Deduplicate
    const uniqueDetails = Array.from(new Set(details));

    // Compute severity & score
    const severity = isThreat
        ? getMaxSeverity(uniqueDetails, severityMap)
        : 'low';
    const score = SEVERITY_TO_SCORE[severity];

    return {
        isThreat,
        method,
        details: uniqueDetails,
        severity,
        score,
        meta,
    };
}

/**
 * Default detection result used as a safe fallback
 */
export const DEFAULT_DETECTION_RESULT: DetectionResult = {
    isThreat: false,
    method: 'unknown',
    details: [],
    severity: 'low',
    score: SEVERITY_TO_SCORE.low,
};

/**
 * Calculates Levenshtein distance between two strings
 * @param a - First string
 * @param b - Second string
 * @returns Number of single-character edits required
 */
export function levenshteinDistance(a: string, b: string): number {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix = Array.from({ length: b.length + 1 }, () =>
        Array(a.length + 1).fill(0)
    );
    for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
    for (let j = 0; j <= b.length; j++) matrix[j][0] = j;

    for (let j = 1; j <= b.length; j++) {
        for (let i = 1; i <= a.length; i++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            matrix[j][i] = Math.min(
                matrix[j][i - 1] + 1,
                matrix[j - 1][i] + 1,
                matrix[j - 1][i - 1] + cost
            );
        }
    }
    return matrix[b.length][a.length];
}

/**
 * Aggregates multiple DetectionResults into one
 * @param results - Array of DetectionResult
 * @returns Aggregated DetectionResult
 */
export function aggregateDetection(results: DetectionResult[]): DetectionResult {
    if (results.length === 0) return DEFAULT_DETECTION_RESULT;

    const allDetails = Array.from(
        new Set(results.flatMap(r => r.details))
    );
    const avgScore =
        results.reduce((sum, r) => sum + r.score, 0) / results.length;
    const maxSeverity = results.reduce<Severity>(
        (max, r) =>
            SEVERITY_TO_SCORE[r.severity] > SEVERITY_TO_SCORE[max]
                ? r.severity
                : max,
        'low'
    );
    const combinedMeta = results.reduce<Record<string, unknown>>((m, r) => {
        if (r.meta) m[r.method] = r.meta;
        return m;
    }, {});

    return {
        isThreat: results.some(r => r.isThreat),
        method: 'unknown',
        details: allDetails,
        severity: maxSeverity,
        score: avgScore,
        meta: {
            sourceResults: results.map(r => r.method),
            ...combinedMeta,
        },
    };
}
