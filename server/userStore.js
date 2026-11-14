/*
 * SENTINEL LOGIN PORTAL
 * User Account Store
 *
 * Stores accounts (username + password hash only) in a local JSON file.
 * Writes are serialized and atomic (write temp file, then rename).
 * The file must never be committed to Git.
 */

import fs from "node:fs/promises";
import path from "node:path";

export class UserStore {

    #filePath;
    #maxUsers;
    #users = new Map();
    #writeQueue = Promise.resolve();

    /**
     * @param {string} filePath - JSON file used for persistence
     * @param {Object} [options]
     * @param {number} [options.maxUsers] - Maximum stored accounts
     */
    constructor(filePath, { maxUsers = 1000 } = {}) {
        this.#filePath = filePath;
        this.#maxUsers = maxUsers;
    }


    /**
     * Loads accounts from disk. A missing file is treated as empty.
     * A corrupted file throws so it is never silently overwritten.
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

        let parsed;

        try {
            parsed = JSON.parse(rawContent);
        } catch {
            throw new Error("User store is corrupted and was not loaded.");
        }

        if (!parsed || !Array.isArray(parsed.users)) {
            throw new Error("User store has an unexpected format.");
        }

        for (const record of parsed.users) {

            if (
                record &&
                typeof record.username === "string" &&
                typeof record.passwordHash === "string"
            ) {
                this.#users.set(record.username.toLowerCase(), {
                    username: record.username,
                    passwordHash: record.passwordHash,
                    createdAt: typeof record.createdAt === "string"
                        ? record.createdAt
                        : new Date(0).toISOString()
                });
            }
        }
    }


    /** @returns {number} Number of stored accounts */
    get size() {
        return this.#users.size;
    }


    /**
     * Looks up an account (case-insensitive).
     *
     * @param {unknown} username
     * @returns {{username: string, passwordHash: string}|undefined}
     */
    get(username) {

        if (typeof username !== "string") {
            return undefined;
        }

        return this.#users.get(username.toLowerCase());
    }


    /**
     * Creates and persists an account.
     *
     * @param {string} username - Validated username
     * @param {string} passwordHash - Hash from hashPassword
     * @throws Error with code USERNAME_TAKEN or USER_LIMIT
     */
    async create(username, passwordHash) {

        const key = username.toLowerCase();

        if (this.#users.has(key)) {
            throw Object.assign(
                new Error("Username already exists."),
                { code: "USERNAME_TAKEN" }
            );
        }

        if (this.#users.size >= this.#maxUsers) {
            throw Object.assign(
                new Error("Account limit reached."),
                { code: "USER_LIMIT" }
            );
        }

        const record = {
            username,
            passwordHash,
            createdAt: new Date().toISOString()
        };

        /* Reserve the name synchronously to prevent duplicate races. */

        this.#users.set(key, record);

        try {
            await this.#persist();
        } catch (error) {
            this.#users.delete(key);
            throw error;
        }

        return record;
    }


    #persist() {

        const writeFile = async () => {

            const payload = JSON.stringify(
                { version: 1, users: [...this.#users.values()] },
                null,
                2
            );

            const temporaryPath = `${this.#filePath}.tmp`;

            await fs.mkdir(path.dirname(this.#filePath), { recursive: true });

            await fs.writeFile(temporaryPath, payload, {
                encoding: "utf8",
                mode: 0o600
            });

            await fs.rename(temporaryPath, this.#filePath);
        };

        const result = this.#writeQueue.then(writeFile, writeFile);

        this.#writeQueue = result.catch(() => {});

        return result;
    }
}
