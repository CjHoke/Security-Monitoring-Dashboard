/*
 * SENTINEL LOGIN PORTAL
 * Password Hashing
 *
 * Uses Node's built-in scrypt with a unique random salt per password.
 * Stored format: scrypt$N$r$p$saltHex$hashHex
 */

import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);

const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

const SCRYPT_COST = 16384;
const SCRYPT_BLOCK_SIZE = 8;
const SCRYPT_PARALLELIZATION = 1;

const MAX_ACCEPTED_COST = 2 ** 17;


/**
 * Hashes a password for storage.
 *
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Encoded password hash
 */
export async function hashPassword(password) {

    const salt = crypto.randomBytes(SALT_LENGTH);

    const derivedKey = await scrypt(password, salt, KEY_LENGTH, {
        N: SCRYPT_COST,
        r: SCRYPT_BLOCK_SIZE,
        p: SCRYPT_PARALLELIZATION
    });

    return [
        "scrypt",
        SCRYPT_COST,
        SCRYPT_BLOCK_SIZE,
        SCRYPT_PARALLELIZATION,
        salt.toString("hex"),
        derivedKey.toString("hex")
    ].join("$");
}


/**
 * Verifies a password against a stored hash using a
 * constant-time comparison. Malformed hashes never verify.
 *
 * @param {string} password - Plain text password
 * @param {string} storedHash - Encoded hash from hashPassword
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, storedHash) {

    if (typeof password !== "string" || typeof storedHash !== "string") {
        return false;
    }

    const parts = storedHash.split("$");

    if (parts.length !== 6 || parts[0] !== "scrypt") {
        return false;
    }

    const [, costText, blockText, parallelText, saltHex, hashHex] = parts;

    const cost = Number.parseInt(costText, 10);
    const blockSize = Number.parseInt(blockText, 10);
    const parallelization = Number.parseInt(parallelText, 10);

    if (
        !Number.isInteger(cost) || cost < 2 || cost > MAX_ACCEPTED_COST ||
        !Number.isInteger(blockSize) || blockSize < 1 || blockSize > 16 ||
        !Number.isInteger(parallelization) ||
        parallelization < 1 || parallelization > 4
    ) {
        return false;
    }

    if (!/^[0-9a-f]+$/i.test(saltHex) || !/^[0-9a-f]+$/i.test(hashHex)) {
        return false;
    }

    const expected = Buffer.from(hashHex, "hex");

    if (expected.length === 0) {
        return false;
    }

    try {

        const actual = await scrypt(
            password,
            Buffer.from(saltHex, "hex"),
            expected.length,
            {
                N: cost,
                r: blockSize,
                p: parallelization,
                maxmem: 128 * cost * blockSize * 2
            }
        );

        return crypto.timingSafeEqual(actual, expected);

    } catch {
        return false;
    }
}


let dummyHashPromise = null;

/**
 * Performs a full password verification against a throwaway hash.
 *
 * Called when a username does not exist so that unknown and known
 * usernames take similar time, limiting username enumeration.
 *
 * @param {string} password - Plain text password
 * @returns {Promise<boolean>} Always false
 */
export async function verifyAgainstDummyHash(password) {

    dummyHashPromise ??= hashPassword(
        crypto.randomBytes(24).toString("hex")
    );

    await verifyPassword(password, await dummyHashPromise);

    return false;
}
