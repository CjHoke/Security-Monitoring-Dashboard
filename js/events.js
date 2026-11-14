
/*
 * SENTINEL SECURITY MONITORING DASHBOARD
 * Authentication Event Generator
 *
 * Responsible for:
 * - Creating authentication events
 * - Providing initial sample events
 * - Generating random login activity
 * - Simulating brute-force attacks
 * - Managing event simulation intervals
 */

let eventCounter = 1;


/* =========================================
   EVENT CREATION
========================================= */

/**
 * Creates a standardized authentication event.
 *
 * @param {string} type - FAILED_LOGIN or SUCCESS_LOGIN
 * @param {string} sourceIp - Originating IP address
 * @param {string} username - Account involved
 * @param {Date} timestamp - Event timestamp
 * @returns {Object} Authentication event
 */
function createEvent(type, sourceIp, username, timestamp = new Date()) {

    if (!["FAILED_LOGIN", "SUCCESS_LOGIN"].includes(type)) {
        throw new Error(`Invalid authentication event type: ${type}`);
    }

    const eventDate = new Date(timestamp);

    if (Number.isNaN(eventDate.getTime())) {
        throw new Error("Invalid event timestamp.");
    }

    const status = type === "FAILED_LOGIN" ? "FAILED" : "SUCCESS";

    return {
        id: `event-${eventCounter++}`,
        timestamp: eventDate.toISOString(),
        sourceIp,
        username,
        type,
        status
    };
}


/* =========================================
   INITIAL SAMPLE EVENTS
========================================= */

/**
 * Creates sample events for dashboard initialization.
 *
 * Includes repeated failed logins from one IP
 * to demonstrate threat detection immediately.
 *
 * @returns {Array} Initial authentication events
 */
export function getInitialEvents() {

    const now = Date.now();

    const sampleEvents = [

        createEvent(
            "SUCCESS_LOGIN",
            "192.0.2.10",
            "jsmith",
            new Date(now - 420000)
        ),

        createEvent(
            "FAILED_LOGIN",
            "198.51.100.27",
            "admin",
            new Date(now - 360000)
        ),

        createEvent(
            "SUCCESS_LOGIN",
            "192.0.2.15",
            "mrivera",
            new Date(now - 300000)
        ),

        createEvent(
            "FAILED_LOGIN",
            "203.0.113.42",
            "admin",
            new Date(now - 110000)
        ),

        createEvent(
            "FAILED_LOGIN",
            "203.0.113.42",
            "admin",
            new Date(now - 75000)
        ),

        createEvent(
            "SUCCESS_LOGIN",
            "192.0.2.10",
            "jsmith",
            new Date(now - 50000)
        ),

        createEvent(
            "FAILED_LOGIN",
            "203.0.113.42",
            "admin",
            new Date(now - 35000)
        ),

        createEvent(
            "FAILED_LOGIN",
            "198.51.100.27",
            "root",
            new Date(now - 25000)
        )

    ];

    return sampleEvents;
}


/* =========================================
   RANDOM EVENT GENERATION
========================================= */

/**
 * Generates a randomized authentication event.
 *
 * @returns {Object} Random authentication event
 */
export function createRandomEvent() {

    const ipAddresses = [
        "192.0.2.10",
        "192.0.2.15",
        "198.51.100.27",
        "198.51.100.88",
        "203.0.113.73"
    ];

    const usernames = [
        "admin",
        "jsmith",
        "mrivera",
        "root",
        "svc_backup",
        "operator"
    ];

    const isFailedLogin = Math.random() < 0.30;

    const eventType = isFailedLogin
        ? "FAILED_LOGIN"
        : "SUCCESS_LOGIN";

    const sourceIp = ipAddresses[
        Math.floor(Math.random() * ipAddresses.length)
    ];

    const username = usernames[
        Math.floor(Math.random() * usernames.length)
    ];

    return createEvent(
        eventType,
        sourceIp,
        username
    );
}


/* =========================================
   BRUTE-FORCE ATTACK SIMULATION
========================================= */

/**
 * Generates multiple failed login attempts
 * from a single IP within a short time window.
 *
 * @param {Object} options - Attack configuration
 * @returns {Array} Generated failed login events
 */
export function generateBruteForceEvents(options = {}) {

    const attempts = options.attempts ?? 5;
    const sourceIp = options.sourceIp ?? "203.0.113.250";
    const username = options.username ?? "admin";

    if (!Number.isInteger(attempts) || attempts < 3 || attempts > 20) {
        throw new RangeError("Attack attempts must be between 3 and 20.");
    }

    const generatedEvents = [];

    for (let index = 0; index < attempts; index++) {

        const secondsAgo = (attempts - index - 1) * 15;

        const timestamp = new Date(
            Date.now() - secondsAgo * 1000
        );

        const event = createEvent(
            "FAILED_LOGIN",
            sourceIp,
            username,
            timestamp
        );

        generatedEvents.push(event);
    }

    return generatedEvents;
}


/* =========================================
   EVENT SIMULATION CONTROLS
========================================= */

/**
 * Starts automatic event generation.
 *
 * @param {Function} onEvent - Callback receiving each event
 * @param {number} intervalMs - Time between generated events
 * @returns {number} Simulation interval ID
 */
export function startEventSimulation(onEvent, intervalMs = 4000) {

    if (typeof onEvent !== "function") {
        throw new TypeError("onEvent must be a function.");
    }

    if (!Number.isFinite(intervalMs) || intervalMs < 500) {
        throw new RangeError("Simulation interval must be at least 500ms.");
    }

    return setInterval(() => {

        const event = createRandomEvent();

        onEvent(event);

    }, intervalMs);
}


/**
 * Stops automatic event generation.
 *
 * @param {number} intervalId - Interval returned by startEventSimulation
 */
export function stopEventSimulation(intervalId) {

    if (intervalId !== null && intervalId !== undefined) {
        clearInterval(intervalId);
    }
}
