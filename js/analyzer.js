
/*
 * SENTINEL SECURITY MONITORING DASHBOARD
 * Security Event Analyzer
 *
 * Responsible for:
 * - Validating authentication events
 * - Counting login activity
 * - Tracking failed login attempts by IP
 * - Detecting brute-force attacks
 * - Generating structured security alerts
 *
 * Default detection rule:
 * 3 or more failed login attempts
 * from the same IP within 5 minutes.
 */


/* =========================================
   DETECTION CONFIGURATION
========================================= */

export const DEFAULT_DETECTION_THRESHOLD = 3;

export const DEFAULT_DETECTION_WINDOW_MS = 5 * 60 * 1000;

const VALID_EVENT_TYPES = new Set([
    "FAILED_LOGIN",
    "SUCCESS_LOGIN"
]);


/* =========================================
   EVENT VALIDATION
========================================= */

/**
 * Validates and normalizes an authentication event.
 *
 * @param {Object} event - Authentication event
 * @returns {Object|null} Normalized event or null
 */
function normalizeEvent(event) {

    if (!event || typeof event !== "object") {
        return null;
    }

    if (
        typeof event.sourceIp !== "string" ||
        event.sourceIp.trim() === ""
    ) {
        return null;
    }

    if (!VALID_EVENT_TYPES.has(event.type)) {
        return null;
    }

    const timestamp = Date.parse(event.timestamp);

    if (!Number.isFinite(timestamp)) {
        return null;
    }

    return {
        originalEvent: event,
        sourceIp: event.sourceIp.trim(),
        username: typeof event.username === "string"
            ? event.username
            : "unknown",
        type: event.type,
        timestamp
    };
}


/* =========================================
   MAIN SECURITY ANALYSIS
========================================= */

/**
 * Analyzes authentication events and identifies
 * potentially suspicious login behavior.
 *
 * @param {Array} events - Authentication event collection
 * @param {Object} options - Detection configuration
 *
 * @returns {Object} Security analysis results
 */
export function analyzeEvents(events, options = {}) {

    if (!Array.isArray(events)) {
        throw new TypeError("Events must be provided as an array.");
    }

    const threshold =
        options.threshold ?? DEFAULT_DETECTION_THRESHOLD;

    const windowMs =
        options.windowMs ?? DEFAULT_DETECTION_WINDOW_MS;


    /* Validate detection configuration */

    if (!Number.isInteger(threshold) || threshold < 2) {
        throw new RangeError(
            "Detection threshold must be an integer of at least 2."
        );
    }

    if (!Number.isFinite(windowMs) || windowMs <= 0) {
        throw new RangeError(
            "Detection window must be a positive number."
        );
    }


    /* Normalize incoming events */

    const normalizedEvents = events
        .map(normalizeEvent)
        .filter(event => event !== null);


    /* Calculate authentication statistics */

    const failedLogins = normalizedEvents.filter(
        event => event.type === "FAILED_LOGIN"
    ).length;

    const successfulLogins = normalizedEvents.filter(
        event => event.type === "SUCCESS_LOGIN"
    ).length;


    /* Group failed logins by originating IP */

    const failedAttemptsByIp = new Map();

    for (const event of normalizedEvents) {

        if (event.type !== "FAILED_LOGIN") {
            continue;
        }

        if (!failedAttemptsByIp.has(event.sourceIp)) {
            failedAttemptsByIp.set(event.sourceIp, []);
        }

        failedAttemptsByIp.get(event.sourceIp).push(event);
    }


    /* Analyze each IP independently */

    const alerts = [];

    for (const [sourceIp, attempts] of failedAttemptsByIp) {

        /*
         * Sort attempts chronologically.
         * This allows us to analyze a sliding time window.
         */

        attempts.sort(
            (a, b) => a.timestamp - b.timestamp
        );

        let left = 0;
        let latestQualifyingWindow = null;


        /*
         * Sliding window algorithm:
         *
         * Expand the right side as new events are processed.
         * Move the left side forward when an event becomes
         * older than the configured detection window.
         */

        for (let right = 0; right < attempts.length; right++) {

            while (
                attempts[right].timestamp -
                attempts[left].timestamp > windowMs
            ) {
                left++;
            }

            const attemptCount = right - left + 1;

            /*
             * A suspicious pattern is identified when
             * the threshold is reached inside the window.
             */

            if (attemptCount >= threshold) {

                const currentWindow = attempts.slice(
                    left,
                    right + 1
                );

                latestQualifyingWindow = {
                    attemptCount,
                    firstSeen: currentWindow[0].timestamp,
                    lastSeen: currentWindow[currentWindow.length - 1].timestamp,

                    usernames: [
                        ...new Set(
                            currentWindow.map(event => event.username)
                        )
                    ]
                };
            }
        }


        /* Generate one alert per suspicious IP */

        if (latestQualifyingWindow) {

            const detectionWindowMinutes =
                windowMs / 60000;

            alerts.push({

                id: `brute-force-${sourceIp}`,

                type: "BRUTE_FORCE",

                severity: "HIGH",

                title: "Possible Brute-Force Attack",

                sourceIp,

                attemptCount: latestQualifyingWindow.attemptCount,

                threshold,

                windowMs,

                firstSeen: new Date(
                    latestQualifyingWindow.firstSeen
                ).toISOString(),

                lastSeen: new Date(
                    latestQualifyingWindow.lastSeen
                ).toISOString(),

                usernames: latestQualifyingWindow.usernames,

                description:
                    `${latestQualifyingWindow.attemptCount} failed login attempts ` +
                    `from ${sourceIp} within ${detectionWindowMinutes} minutes.`

            });
        }
    }


    /* Sort alerts with most recent activity first */

    alerts.sort(
        (a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen)
    );


    /* Return complete analysis results */

    return {

        totalEvents: normalizedEvents.length,

        failedLogins,

        successfulLogins,

        suspiciousIps: alerts.length,

        malformedEvents: events.length - normalizedEvents.length,

        alerts,

        suspiciousIpAddresses: alerts.map(
            alert => alert.sourceIp
        )

    };
}
