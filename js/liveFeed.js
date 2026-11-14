/*
 * SENTINEL SECURITY MONITORING DASHBOARD
 * Live Authentication Feed
 *
 * Responsible for:
 * - Polling the local Sentinel server for new authentication events
 * - Requesting only events newer than the last one received
 * - Validating every received event (treated as untrusted input)
 * - Backing off when the server is unreachable
 *
 * If the dashboard is opened without the Sentinel server (for example
 * through a static file server), the feed simply reports "offline" and
 * the existing simulation continues to work.
 */

const DEFAULT_ENDPOINT = "/api/events";

const REQUEST_TIMEOUT_MS = 3000;

const MAX_BACKOFF_MS = 15000;

const MIN_INTERVAL_MS = 100;


/**
 * @param {unknown} data - Parsed feed response
 * @returns {boolean} True when the response has the expected shape
 */
function isValidFeedResponse(data) {

    return Boolean(
        data &&
        typeof data === "object" &&
        Array.isArray(data.events) &&
        Number.isInteger(data.latestSeq) &&
        data.latestSeq >= 0
    );
}


/**
 * @param {unknown} event - Event received from the server
 * @returns {boolean} True when the event is safe for the dashboard
 */
function isUsableEvent(event) {

    return Boolean(
        event &&
        typeof event === "object" &&
        typeof event.id === "string" &&
        typeof event.sourceIp === "string" &&
        event.sourceIp.trim() !== "" &&
        typeof event.username === "string" &&
        typeof event.type === "string" &&
        typeof event.status === "string" &&
        Number.isFinite(Date.parse(event.timestamp))
    );
}


/**
 * Starts polling the Sentinel server for authentication events.
 *
 * @param {Object} options
 * @param {Function} options.onEvents - Called with (events, {initial})
 *        when the first response arrives and whenever new events appear.
 *        `initial` is true for the first response (the existing backlog).
 * @param {Function} [options.onStatus] - Called with ({online}) whenever
 *        connectivity changes.
 * @param {string} [options.endpoint] - Feed URL
 * @param {number} [options.intervalMs] - Poll interval
 * @returns {{stop: Function}} Controller that stops polling
 */
export function startLiveFeed({
    onEvents,
    onStatus = () => {},
    endpoint = DEFAULT_ENDPOINT,
    intervalMs = 2000
} = {}) {

    if (typeof onEvents !== "function") {
        throw new TypeError("onEvents must be a function.");
    }

    if (!Number.isFinite(intervalMs) || intervalMs < MIN_INTERVAL_MS) {
        throw new RangeError(
            `Poll interval must be at least ${MIN_INTERVAL_MS}ms.`
        );
    }

    let lastSeq = null;
    let lastOnline = null;
    let consecutiveFailures = 0;
    let stopped = false;
    let timerId = null;


    function reportStatus(online) {

        if (online !== lastOnline) {
            lastOnline = online;
            onStatus({ online });
        }
    }


    async function poll() {

        let nextDelay = intervalMs;

        const controller = new AbortController();

        const timeoutId = setTimeout(
            () => controller.abort(),
            REQUEST_TIMEOUT_MS
        );

        try {

            const url = lastSeq === null
                ? endpoint
                : `${endpoint}?after=${lastSeq}`;

            const response = await fetch(url, {
                cache: "no-store",
                signal: controller.signal
            });

            if (!response.ok) {
                throw new Error(`Unexpected status ${response.status}`);
            }

            const data = await response.json();

            if (!isValidFeedResponse(data)) {
                throw new Error("Unexpected feed response format.");
            }

            if (stopped) {
                return;
            }

            consecutiveFailures = 0;

            reportStatus(true);

            if (lastSeq !== null && data.latestSeq < lastSeq) {

                /*
                 * The server's event history was reset.
                 * Start over so the dashboard reloads the backlog.
                 */

                lastSeq = null;
                nextDelay = MIN_INTERVAL_MS;

            } else {

                const initial = lastSeq === null;

                lastSeq = data.latestSeq;

                const usableEvents = data.events.filter(isUsableEvent);

                if (initial || usableEvents.length > 0) {
                    onEvents(usableEvents, { initial });
                }
            }

        } catch {

            consecutiveFailures++;

            nextDelay = Math.min(
                intervalMs * 2 ** consecutiveFailures,
                MAX_BACKOFF_MS
            );

            reportStatus(false);

        } finally {

            clearTimeout(timeoutId);

            if (!stopped) {
                timerId = setTimeout(poll, nextDelay);
            }
        }
    }


    poll();


    return {

        stop() {
            stopped = true;
            clearTimeout(timerId);
        }
    };
}
