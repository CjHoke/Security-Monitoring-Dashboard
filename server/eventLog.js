/*
 * SENTINEL LOGIN PORTAL
 * Authentication Event Log
 *
 * Records every login attempt in the exact event format the Sentinel
 * analyzer already understands, plus a few extra fields:
 *
 *   {
 *     id, seq, timestamp, sourceIp, username,
 *     type:   "FAILED_LOGIN" | "SUCCESS_LOGIN",
 *     status: "FAILED" | "SUCCESS",
 *     reason, source
 *   }
 *
 * Events are appended to a JSON Lines file and the most recent ones
 * are kept in memory for the dashboard feed. The file must never be
 * committed to Git.
 */

import fs from "node:fs/promises";
import path from "node:path";

const VALID_TYPES = new Set(["FAILED_LOGIN", "SUCCESS_LOGIN"]);

export const DEFAULT_MAX_MEMORY_EVENTS = 2000;

export const DEFAULT_MAX_FILE_EVENTS = 10000;


/**
 * @param {unknown} event - Parsed JSON line
 * @returns {boolean} True when the stored event is well formed
 */
function isValidStoredEvent(event) {

    return Boolean(
        event &&
        typeof event === "object" &&
        Number.isInteger(event.seq) &&
        event.seq > 0 &&
        VALID_TYPES.has(event.type) &&
        typeof event.sourceIp === "string" &&
        typeof event.username === "string" &&
        typeof event.timestamp === "string" &&
        Number.isFinite(Date.parse(event.timestamp))
    );
}


export class EventLog {

    #filePath;
    #maxMemoryEvents;
    #maxFileEvents;
    #events = [];
    #seq = 0;
    #writeQueue = Promise.resolve();

    /**
     * @param {string} filePath - JSON Lines file for persistence
     * @param {Object} [options]
     * @param {number} [options.maxMemoryEvents] - Events kept in memory
     * @param {number} [options.maxFileEvents] - Retention limit on disk
     */
    constructor(filePath, {
        maxMemoryEvents = DEFAULT_MAX_MEMORY_EVENTS,
        maxFileEvents = DEFAULT_MAX_FILE_EVENTS
    } = {}) {
        this.#filePath = filePath;
        this.#maxMemoryEvents = maxMemoryEvents;
        this.#maxFileEvents = maxFileEvents;
    }


    /**
     * Loads recent events from disk, skipping malformed lines.
     * Trims the file when it exceeds the retention limit.
     */
    async load() {

        let rawContent;

        try {
            rawContent = await fs.readFile(this.#filePath, "utf8");
        } catch (error) {

            if (error.code === "ENOENT") {
                return;
            }

            throw error;
        }

        const storedEvents = [];

        for (const line of rawContent.split("\n")) {

            if (line.trim() === "") {
                continue;
            }

            try {

                const parsed = JSON.parse(line);

                if (isValidStoredEvent(parsed)) {
                    storedEvents.push(parsed);
                }

            } catch {
                /* Skip corrupted lines. */
            }
        }

        this.#events = storedEvents.slice(-this.#maxMemoryEvents);

        this.#seq = storedEvents.reduce(
            (highest, event) => Math.max(highest, event.seq),
            0
        );

        if (storedEvents.length > this.#maxFileEvents) {

            const retained = storedEvents.slice(
                -Math.floor(this.#maxFileEvents / 2)
            );

            const temporaryPath = `${this.#filePath}.tmp`;

            await fs.writeFile(
                temporaryPath,
                retained.map(event => JSON.stringify(event)).join("\n") + "\n",
                { encoding: "utf8", mode: 0o600 }
            );

            await fs.rename(temporaryPath, this.#filePath);
        }
    }


    /** @returns {number} Highest assigned sequence number */
    get latestSeq() {
        return this.#seq;
    }


    /**
     * Records one authentication attempt.
     *
     * @param {Object} details
     * @param {"FAILED_LOGIN"|"SUCCESS_LOGIN"} details.type
     * @param {string} details.sourceIp - Normalized client IP
     * @param {string} details.username - Sanitized username
     * @param {string} details.reason - Short machine-readable reason
     * @param {Date} [timestamp] - Event time
     * @returns {Promise<Object>} The stored event
     */
    async append({ type, sourceIp, username, reason }, timestamp = new Date()) {

        if (!VALID_TYPES.has(type)) {
            throw new TypeError(`Invalid authentication event type: ${type}`);
        }

        const seq = ++this.#seq;

        const event = {
            id: `login-${seq}`,
            seq,
            timestamp: timestamp.toISOString(),
            sourceIp,
            username,
            type,
            status: type === "FAILED_LOGIN" ? "FAILED" : "SUCCESS",
            reason,
            source: "SENTINEL_LOGIN"
        };

        this.#events.push(event);

        if (this.#events.length > this.#maxMemoryEvents) {
            this.#events = this.#events.slice(-this.#maxMemoryEvents);
        }

        await this.#appendLine(JSON.stringify(event) + "\n");

        return event;
    }


    /**
     * Returns events for the dashboard feed.
     *
     * With no `after` value, returns the most recent events.
     * With `after`, returns events newer than that sequence number.
     *
     * @param {Object} [options]
     * @param {number|null} [options.after] - Last sequence already seen
     * @param {number} [options.limit] - Maximum events returned
     * @returns {Array<Object>}
     */
    getEvents({ after = null, limit = 500 } = {}) {

        if (after === null) {
            return this.#events.slice(-limit);
        }

        return this.#events
            .filter(event => event.seq > after)
            .slice(0, limit);
    }


    #appendLine(line) {

        const write = async () => {

            await fs.mkdir(path.dirname(this.#filePath), { recursive: true });

            await fs.appendFile(this.#filePath, line, {
                encoding: "utf8",
                mode: 0o600
            });
        };

        const result = this.#writeQueue.then(write, write);

        this.#writeQueue = result.catch(() => {});

        return result;
    }
}
