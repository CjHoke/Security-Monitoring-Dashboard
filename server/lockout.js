/*
 * SENTINEL LOGIN PORTAL
 * Account Lockout and Rate Limiting
 *
 * - LockoutTracker: temporarily locks an account name after repeated
 *   failures. Applies to unknown usernames too, so lockout behavior
 *   never reveals whether an account exists.
 * - SlidingWindowLimiter: limits how often a key (e.g. an IP address)
 *   may perform an action, used for account creation.
 *
 * Login attempts are deliberately NOT rate limited per IP: every
 * attempt must reach the event log so Sentinel can detect attacks.
 */

export class LockoutTracker {

    #records = new Map();
    #maxFailures;
    #failureWindowMs;
    #lockDurationMs;
    #maxTrackedKeys;
    #now;

    /**
     * @param {Object} [options]
     * @param {number} [options.maxFailures] - Failures before lockout
     * @param {number} [options.failureWindowMs] - Window counting failures
     * @param {number} [options.lockDurationMs] - Lockout length
     * @param {number} [options.maxTrackedKeys] - Memory bound
     * @param {Function} [options.now] - Clock, replaceable in tests
     */
    constructor({
        maxFailures = 5,
        failureWindowMs = 15 * 60 * 1000,
        lockDurationMs = 5 * 60 * 1000,
        maxTrackedKeys = 10000,
        now = Date.now
    } = {}) {
        this.#maxFailures = maxFailures;
        this.#failureWindowMs = failureWindowMs;
        this.#lockDurationMs = lockDurationMs;
        this.#maxTrackedKeys = maxTrackedKeys;
        this.#now = now;
    }


    /**
     * @param {string} key - Lowercased account name
     * @returns {{locked: boolean, retryAfterMs: number}}
     */
    getLockState(key) {

        const record = this.#records.get(key);
        const currentTime = this.#now();

        if (record && record.lockedUntil > currentTime) {
            return {
                locked: true,
                retryAfterMs: record.lockedUntil - currentTime
            };
        }

        return { locked: false, retryAfterMs: 0 };
    }


    /**
     * Records a failed attempt and returns the resulting lock state.
     *
     * @param {string} key - Lowercased account name
     * @returns {{locked: boolean, retryAfterMs: number}}
     */
    recordFailure(key) {

        const currentTime = this.#now();

        const record = this.#records.get(key) ??
            { failures: [], lockedUntil: 0 };

        record.failures = record.failures.filter(
            timestamp => currentTime - timestamp < this.#failureWindowMs
        );

        record.failures.push(currentTime);

        if (record.failures.length >= this.#maxFailures) {
            record.lockedUntil = currentTime + this.#lockDurationMs;
            record.failures = [];
        }

        this.#records.delete(key);
        this.#records.set(key, record);

        this.#evictIfNeeded(currentTime);

        return this.getLockState(key);
    }


    /** @param {string} key - Lowercased account name */
    recordSuccess(key) {
        this.#records.delete(key);
    }


    #evictIfNeeded(currentTime) {

        if (this.#records.size <= this.#maxTrackedKeys) {
            return;
        }

        /* Evict the oldest entry that is not currently locked. */

        for (const [candidateKey, record] of this.#records) {

            if (record.lockedUntil <= currentTime) {
                this.#records.delete(candidateKey);
                return;
            }
        }
    }
}


export class SlidingWindowLimiter {

    #hits = new Map();
    #limit;
    #windowMs;
    #now;

    /**
     * @param {Object} options
     * @param {number} options.limit - Actions allowed per window
     * @param {number} options.windowMs - Window length
     * @param {Function} [options.now] - Clock, replaceable in tests
     */
    constructor({ limit, windowMs, now = Date.now }) {
        this.#limit = limit;
        this.#windowMs = windowMs;
        this.#now = now;
    }


    /**
     * Attempts to use one action for a key.
     *
     * @param {string} key - Limited subject (e.g. IP address)
     * @returns {boolean} False when the limit has been reached
     */
    tryConsume(key) {

        const currentTime = this.#now();

        if (this.#hits.size > 10000) {
            this.#pruneExpired(currentTime);
        }

        const recent = (this.#hits.get(key) ?? []).filter(
            timestamp => currentTime - timestamp < this.#windowMs
        );

        if (recent.length >= this.#limit) {
            this.#hits.set(key, recent);
            return false;
        }

        recent.push(currentTime);
        this.#hits.set(key, recent);

        return true;
    }


    #pruneExpired(currentTime) {

        for (const [key, timestamps] of this.#hits) {

            const hasRecent = timestamps.some(
                timestamp => currentTime - timestamp < this.#windowMs
            );

            if (!hasRecent) {
                this.#hits.delete(key);
            }
        }
    }
}
