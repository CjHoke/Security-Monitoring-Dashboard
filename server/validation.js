/*
 * SENTINEL LOGIN PORTAL
 * Input Validation Helpers
 *
 * Responsible for:
 * - Validating usernames and passwords for account creation
 * - Sanitizing untrusted usernames before they are logged
 * - Normalizing client IP addresses
 */

import net from "node:net";

export const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{3,32}$/;

export const PASSWORD_MIN_LENGTH = 8;

export const PASSWORD_MAX_LENGTH = 128;

export const MAX_LOGGED_USERNAME_LENGTH = 64;


/**
 * Validates credentials supplied for account creation.
 *
 * @param {unknown} username - Requested username
 * @param {unknown} password - Requested password
 * @returns {{valid: boolean, error?: string}}
 */
export function validateRegistration(username, password) {

    if (typeof username !== "string" || !USERNAME_PATTERN.test(username)) {
        return {
            valid: false,
            error:
                "Username must be 3-32 characters using letters, " +
                "numbers, dots, underscores or hyphens."
        };
    }

    if (
        typeof password !== "string" ||
        password.length < PASSWORD_MIN_LENGTH ||
        password.length > PASSWORD_MAX_LENGTH
    ) {
        return {
            valid: false,
            error:
                `Password must be ${PASSWORD_MIN_LENGTH}-` +
                `${PASSWORD_MAX_LENGTH} characters.`
        };
    }

    if (password.toLowerCase() === username.toLowerCase()) {
        return {
            valid: false,
            error: "Password must not match the username."
        };
    }

    return { valid: true };
}


/**
 * Makes an attacker-controlled username safe to store and display.
 *
 * Removes control and invisible formatting characters (which can be
 * used to spoof log entries), trims whitespace and limits length.
 *
 * @param {unknown} value - Raw username from a request
 * @returns {string} Sanitized username, or "unknown"
 */
export function sanitizeLoggedUsername(value) {

    if (typeof value !== "string") {
        return "unknown";
    }

    const cleaned = value
        .replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, "")
        .trim()
        .slice(0, MAX_LOGGED_USERNAME_LENGTH);

    return cleaned === "" ? "unknown" : cleaned;
}


/**
 * Normalizes a socket address into a plain IP string.
 * IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) become IPv4.
 *
 * @param {unknown} address - Raw remote address
 * @returns {string} Valid IP address, or "unknown"
 */
export function normalizeRemoteAddress(address) {

    if (typeof address !== "string") {
        return "unknown";
    }

    const stripped = address.startsWith("::ffff:")
        ? address.slice(7)
        : address;

    return net.isIP(stripped) ? stripped : "unknown";
}


/**
 * @param {string} address - Normalized IP address
 * @returns {boolean} True for loopback addresses
 */
export function isLoopbackAddress(address) {
    return address === "127.0.0.1" || address === "::1";
}
