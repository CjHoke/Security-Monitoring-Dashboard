/*
 * SENTINEL LOGIN PORTAL TESTS
 *
 * Covers: validation, password hashing, lockout, persistence,
 * the HTTP server, the live feed, and the integration with the
 * existing Sentinel analyzer.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    validateRegistration,
    sanitizeLoggedUsername,
    normalizeRemoteAddress
} from "../server/validation.js";

import {
    hashPassword,
    verifyPassword
} from "../server/passwords.js";

import {
    LockoutTracker,
    SlidingWindowLimiter
} from "../server/lockout.js";

import { UserStore } from "../server/userStore.js";
import { EventLog } from "../server/eventLog.js";
import { createSentinelServer } from "../server/server.js";
import { startLiveFeed } from "../js/liveFeed.js";
import { analyzeEvents } from "../js/analyzer.js";

const projectRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    ".."
);


/* =========================================
   TEST HELPERS
========================================= */

async function makeTempDir() {
    return fs.mkdtemp(path.join(os.tmpdir(), "sentinel-test-"));
}

async function startTestServer(options = {}) {

    const dataDir = await makeTempDir();

    const app = await createSentinelServer({
        projectRoot,
        usersFile: path.join(dataDir, "users.json"),
        eventsFile: path.join(dataDir, "events.jsonl"),
        port: 0,
        ...options
    });

    const { port } = await app.start();

    return {
        app,
        port,
        baseUrl: `http://127.0.0.1:${port}`,
        dataDir,
        async close() {
            await app.stop();
            await fs.rm(dataDir, { recursive: true, force: true });
        }
    };
}

async function postJson(baseUrl, pathname, body, headers = {}) {

    const response = await fetch(baseUrl + pathname, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(body)
    });

    return { status: response.status, body: await response.json() };
}

async function getEvents(baseUrl, query = "") {

    const response = await fetch(`${baseUrl}/api/events${query}`);

    return response.json();
}

/** Sends a raw HTTP request so headers like Host and Origin can be set. */
function rawRequest({ port, method = "GET", requestPath, headers = {}, body }) {

    return new Promise((resolve, reject) => {

        const request = http.request(
            { host: "127.0.0.1", port, method, path: requestPath, headers },
            response => {

                const chunks = [];

                response.on("data", chunk => chunks.push(chunk));

                response.on("end", () => resolve({
                    status: response.statusCode,
                    headers: response.headers,
                    text: Buffer.concat(chunks).toString("utf8")
                }));
            }
        );

        request.on("error", reject);

        request.end(body);
    });
}


/* =========================================
   VALIDATION
========================================= */

test("registration accepts a valid username and password", () => {
    assert.equal(validateRegistration("alice_01", "correct horse").valid, true);
});

test("registration rejects bad usernames", () => {

    for (const username of ["ab", "has space", "bad<script>", "x".repeat(33), "", null, 42]) {
        assert.equal(validateRegistration(username, "correct horse").valid, false);
    }
});

test("registration rejects bad passwords", () => {

    assert.equal(validateRegistration("alice", "short").valid, false);
    assert.equal(validateRegistration("alice", "x".repeat(129)).valid, false);
    assert.equal(validateRegistration("alice", undefined).valid, false);
    assert.equal(validateRegistration("alice123", "ALICE123").valid, false);
});

test("logged usernames are stripped of control characters and truncated", () => {

    assert.equal(sanitizeLoggedUsername("ad\nmin‮"), "admin");
    assert.equal(sanitizeLoggedUsername("   "), "unknown");
    assert.equal(sanitizeLoggedUsername({}), "unknown");
    assert.equal(sanitizeLoggedUsername("a".repeat(200)).length, 64);
});

test("remote addresses are normalized and validated", () => {

    assert.equal(normalizeRemoteAddress("::ffff:127.0.0.1"), "127.0.0.1");
    assert.equal(normalizeRemoteAddress("::1"), "::1");
    assert.equal(normalizeRemoteAddress("203.0.113.9"), "203.0.113.9");
    assert.equal(normalizeRemoteAddress("not-an-ip"), "unknown");
    assert.equal(normalizeRemoteAddress(undefined), "unknown");
});


/* =========================================
   PASSWORD HASHING
========================================= */

test("password hashes verify only for the correct password", async () => {

    const hash = await hashPassword("correct horse battery");

    assert.equal(await verifyPassword("correct horse battery", hash), true);
    assert.equal(await verifyPassword("wrong password", hash), false);
});

test("the same password produces different hashes (unique salts)", async () => {

    const first = await hashPassword("repeatable password");
    const second = await hashPassword("repeatable password");

    assert.notEqual(first, second);
});

test("malformed stored hashes never verify", async () => {

    for (const bad of ["", "plaintext", "scrypt$1$2", "scrypt$x$8$1$aa$bb", null]) {
        assert.equal(await verifyPassword("anything", bad), false);
    }
});


/* =========================================
   LOCKOUT AND RATE LIMITING
========================================= */

test("account locks after repeated failures and unlocks after the duration", () => {

    let currentTime = 1_000_000;

    const tracker = new LockoutTracker({
        maxFailures: 3,
        failureWindowMs: 60_000,
        lockDurationMs: 30_000,
        now: () => currentTime
    });

    assert.equal(tracker.recordFailure("bob").locked, false);
    assert.equal(tracker.recordFailure("bob").locked, false);
    assert.equal(tracker.recordFailure("bob").locked, true);

    assert.equal(tracker.getLockState("bob").locked, true);
    assert.equal(tracker.getLockState("other").locked, false);

    currentTime += 31_000;

    assert.equal(tracker.getLockState("bob").locked, false);
});

test("failures outside the window do not count toward lockout", () => {

    let currentTime = 0;

    const tracker = new LockoutTracker({
        maxFailures: 3,
        failureWindowMs: 10_000,
        now: () => currentTime
    });

    tracker.recordFailure("carol");
    currentTime += 6_000;
    tracker.recordFailure("carol");
    currentTime += 6_000;

    assert.equal(tracker.recordFailure("carol").locked, false);
});

test("a successful login clears recorded failures", () => {

    const tracker = new LockoutTracker({ maxFailures: 2 });

    tracker.recordFailure("dave");
    tracker.recordSuccess("dave");

    assert.equal(tracker.recordFailure("dave").locked, false);
});

test("sliding window limiter blocks after the limit and recovers", () => {

    let currentTime = 0;

    const limiter = new SlidingWindowLimiter({
        limit: 2,
        windowMs: 1000,
        now: () => currentTime
    });

    assert.equal(limiter.tryConsume("ip"), true);
    assert.equal(limiter.tryConsume("ip"), true);
    assert.equal(limiter.tryConsume("ip"), false);
    assert.equal(limiter.tryConsume("other-ip"), true);

    currentTime += 1001;

    assert.equal(limiter.tryConsume("ip"), true);
});


/* =========================================
   PERSISTENCE
========================================= */

test("user store persists accounts and is case-insensitive", async () => {

    const dataDir = await makeTempDir();
    const filePath = path.join(dataDir, "users.json");

    try {

        const store = new UserStore(filePath);
        await store.load();
        await store.create("Alice", "hash-value");

        assert.equal(store.get("alice").username, "Alice");

        await assert.rejects(
            () => store.create("ALICE", "other"),
            { code: "USERNAME_TAKEN" }
        );

        const reloaded = new UserStore(filePath);
        await reloaded.load();

        assert.equal(reloaded.get("ALICE").passwordHash, "hash-value");

    } finally {
        await fs.rm(dataDir, { recursive: true, force: true });
    }
});

test("user store refuses to load a corrupted file", async () => {

    const dataDir = await makeTempDir();
    const filePath = path.join(dataDir, "users.json");

    try {

        await fs.writeFile(filePath, "{ not json");

        await assert.rejects(() => new UserStore(filePath).load());

    } finally {
        await fs.rm(dataDir, { recursive: true, force: true });
    }
});

test("user store handles usernames like __proto__ safely", async () => {

    const dataDir = await makeTempDir();

    try {

        const store = new UserStore(path.join(dataDir, "users.json"));
        await store.load();

        assert.equal(store.get("__proto__"), undefined);

        await store.create("__proto__", "hash");

        assert.equal(store.get("__proto__").username, "__proto__");
        assert.equal(({}).passwordHash, undefined);

    } finally {
        await fs.rm(dataDir, { recursive: true, force: true });
    }
});

test("event log persists events and continues sequence numbers", async () => {

    const dataDir = await makeTempDir();
    const filePath = path.join(dataDir, "events.jsonl");

    try {

        const log = new EventLog(filePath);
        await log.load();

        const first = await log.append({
            type: "FAILED_LOGIN",
            sourceIp: "203.0.113.5",
            username: "admin",
            reason: "BAD_CREDENTIALS"
        });

        assert.equal(first.id, "login-1");
        assert.equal(first.status, "FAILED");

        await fs.appendFile(filePath, "garbage line\n");

        const reloaded = new EventLog(filePath);
        await reloaded.load();

        assert.equal(reloaded.latestSeq, 1);
        assert.equal(reloaded.getEvents().length, 1);

        const next = await reloaded.append({
            type: "SUCCESS_LOGIN",
            sourceIp: "203.0.113.5",
            username: "admin",
            reason: "AUTHENTICATED"
        });

        assert.equal(next.seq, 2);
        assert.equal(reloaded.getEvents({ after: 1 }).length, 1);

    } finally {
        await fs.rm(dataDir, { recursive: true, force: true });
    }
});

test("event log rejects unsupported event types", async () => {

    const dataDir = await makeTempDir();

    try {

        const log = new EventLog(path.join(dataDir, "events.jsonl"));

        await assert.rejects(
            () => log.append({
                type: "SOMETHING_ELSE",
                sourceIp: "1.2.3.4",
                username: "x",
                reason: "x"
            }),
            TypeError
        );

    } finally {
        await fs.rm(dataDir, { recursive: true, force: true });
    }
});

test("event log trims the file beyond the retention limit", async () => {

    const dataDir = await makeTempDir();
    const filePath = path.join(dataDir, "events.jsonl");

    try {

        const log = new EventLog(filePath, { maxFileEvents: 10 });
        await log.load();

        for (let index = 0; index < 12; index++) {
            await log.append({
                type: "FAILED_LOGIN",
                sourceIp: "198.51.100.1",
                username: `user${index}`,
                reason: "BAD_CREDENTIALS"
            });
        }

        const reloaded = new EventLog(filePath, { maxFileEvents: 10 });
        await reloaded.load();

        const lines = (await fs.readFile(filePath, "utf8"))
            .split("\n")
            .filter(Boolean);

        assert.equal(lines.length, 5);
        assert.equal(reloaded.latestSeq, 12);

    } finally {
        await fs.rm(dataDir, { recursive: true, force: true });
    }
});


/* =========================================
   HTTP SERVER
========================================= */

test("server refuses to bind to a non-loopback address by default", async () => {

    await assert.rejects(
        () => createSentinelServer({ projectRoot, host: "0.0.0.0", port: 0 }),
        /non-loopback/
    );
});

test("register then login succeeds and is recorded as a SUCCESS_LOGIN event", async () => {

    const ctx = await startTestServer();

    try {

        const created = await postJson(ctx.baseUrl, "/api/register", {
            username: "Alice",
            password: "correct horse battery"
        });

        assert.equal(created.status, 201);

        const login = await postJson(ctx.baseUrl, "/api/login", {
            username: "alice",
            password: "correct horse battery"
        });

        assert.equal(login.status, 200);
        assert.equal(login.body.username, "Alice");

        const feed = await getEvents(ctx.baseUrl);

        assert.equal(feed.events.length, 1);
        assert.equal(feed.events[0].type, "SUCCESS_LOGIN");
        assert.equal(feed.events[0].status, "SUCCESS");
        assert.equal(feed.events[0].username, "Alice");
        assert.equal(feed.events[0].sourceIp, "127.0.0.1");

    } finally {
        await ctx.close();
    }
});

test("duplicate usernames are rejected case-insensitively", async () => {

    const ctx = await startTestServer();

    try {

        await postJson(ctx.baseUrl, "/api/register", {
            username: "bob",
            password: "correct horse battery"
        });

        const duplicate = await postJson(ctx.baseUrl, "/api/register", {
            username: "BOB",
            password: "another long password"
        });

        assert.equal(duplicate.status, 409);

    } finally {
        await ctx.close();
    }
});

test("invalid registrations are rejected with 400", async () => {

    const ctx = await startTestServer();

    try {

        const result = await postJson(ctx.baseUrl, "/api/register", {
            username: "x",
            password: "short"
        });

        assert.equal(result.status, 400);

    } finally {
        await ctx.close();
    }
});

test("wrong password and unknown user return identical 401 responses", async () => {

    const ctx = await startTestServer();

    try {

        await postJson(ctx.baseUrl, "/api/register", {
            username: "carol",
            password: "correct horse battery"
        });

        const wrongPassword = await postJson(ctx.baseUrl, "/api/login", {
            username: "carol",
            password: "not the password"
        });

        const unknownUser = await postJson(ctx.baseUrl, "/api/login", {
            username: "nobody",
            password: "not the password"
        });

        assert.equal(wrongPassword.status, 401);
        assert.equal(unknownUser.status, 401);
        assert.deepEqual(wrongPassword.body, unknownUser.body);

        const feed = await getEvents(ctx.baseUrl);

        assert.equal(feed.events.length, 2);
        assert.ok(feed.events.every(event => event.type === "FAILED_LOGIN"));

    } finally {
        await ctx.close();
    }
});

test("account locks after repeated failures and logs ACCOUNT_LOCKED", async () => {

    const ctx = await startTestServer();

    try {

        await postJson(ctx.baseUrl, "/api/register", {
            username: "dave",
            password: "correct horse battery"
        });

        for (let attempt = 0; attempt < 5; attempt++) {

            const failure = await postJson(ctx.baseUrl, "/api/login", {
                username: "dave",
                password: "wrong password"
            });

            assert.equal(failure.status, 401);
        }

        const lockedAttempt = await postJson(ctx.baseUrl, "/api/login", {
            username: "dave",
            password: "correct horse battery"
        });

        assert.equal(lockedAttempt.status, 429);
        assert.ok(lockedAttempt.body.retryAfterSeconds > 0);

        const feed = await getEvents(ctx.baseUrl);

        assert.equal(feed.events.length, 6);
        assert.equal(feed.events.at(-1).reason, "ACCOUNT_LOCKED");
        assert.equal(feed.events.at(-1).type, "FAILED_LOGIN");

    } finally {
        await ctx.close();
    }
});

test("lockout also applies to usernames that do not exist", async () => {

    const ctx = await startTestServer();

    try {

        for (let attempt = 0; attempt < 5; attempt++) {
            await postJson(ctx.baseUrl, "/api/login", {
                username: "ghost",
                password: "whatever password"
            });
        }

        const result = await postJson(ctx.baseUrl, "/api/login", {
            username: "ghost",
            password: "whatever password"
        });

        assert.equal(result.status, 429);

    } finally {
        await ctx.close();
    }
});

test("login requires string username and password", async () => {

    const ctx = await startTestServer();

    try {

        const missing = await postJson(ctx.baseUrl, "/api/login", {
            username: "x"
        });

        const wrongTypes = await postJson(ctx.baseUrl, "/api/login", {
            username: { $ne: "" },
            password: ["a"]
        });

        assert.equal(missing.status, 400);
        assert.equal(wrongTypes.status, 400);

    } finally {
        await ctx.close();
    }
});

test("logged usernames cannot spoof log entries", async () => {

    const ctx = await startTestServer();

    try {

        await postJson(ctx.baseUrl, "/api/login", {
            username: "<img src=x>\n{\"fake\":1}‮",
            password: "whatever password"
        });

        const feed = await getEvents(ctx.baseUrl);

        assert.equal(feed.events.length, 1);
        assert.ok(!/[\n‮]/.test(feed.events[0].username));

        const stored = await fs.readFile(
            path.join(ctx.dataDir, "events.jsonl"),
            "utf8"
        );

        assert.equal(stored.split("\n").filter(Boolean).length, 1);

    } finally {
        await ctx.close();
    }
});

test("password hashes are stored, never plain text passwords", async () => {

    const ctx = await startTestServer();

    try {

        await postJson(ctx.baseUrl, "/api/register", {
            username: "erin",
            password: "plaintext-secret-value"
        });

        const stored = await fs.readFile(
            path.join(ctx.dataDir, "users.json"),
            "utf8"
        );

        assert.ok(!stored.includes("plaintext-secret-value"));
        assert.ok(stored.includes("scrypt$"));

    } finally {
        await ctx.close();
    }
});

test("source IP override header is ignored unless explicitly enabled", async () => {

    const ctx = await startTestServer();

    try {

        await postJson(
            ctx.baseUrl,
            "/api/login",
            { username: "spoof", password: "whatever password" },
            { "X-Sentinel-Test-IP": "203.0.113.99" }
        );

        const feed = await getEvents(ctx.baseUrl);

        assert.equal(feed.events[0].sourceIp, "127.0.0.1");

    } finally {
        await ctx.close();
    }
});

test("invalid override IP values are ignored even when the override is enabled", async () => {

    const ctx = await startTestServer({ allowDevIpOverride: true });

    try {

        await postJson(
            ctx.baseUrl,
            "/api/login",
            { username: "spoof", password: "whatever password" },
            { "X-Sentinel-Test-IP": "not an ip" }
        );

        const feed = await getEvents(ctx.baseUrl);

        assert.equal(feed.events[0].sourceIp, "127.0.0.1");

    } finally {
        await ctx.close();
    }
});

test("cross-origin POST requests are rejected", async () => {

    const ctx = await startTestServer();

    try {

        const result = await rawRequest({
            port: ctx.port,
            method: "POST",
            requestPath: "/api/login",
            headers: {
                "Content-Type": "application/json",
                Origin: "http://evil.example"
            },
            body: JSON.stringify({ username: "a", password: "b" })
        });

        assert.equal(result.status, 403);

    } finally {
        await ctx.close();
    }
});

test("requests with an unexpected Host header are rejected", async () => {

    const ctx = await startTestServer();

    try {

        const result = await rawRequest({
            port: ctx.port,
            requestPath: "/api/events",
            headers: { Host: "attacker.example" }
        });

        assert.equal(result.status, 400);

    } finally {
        await ctx.close();
    }
});

test("non-JSON content types and oversized bodies are rejected", async () => {

    const ctx = await startTestServer();

    try {

        const wrongType = await rawRequest({
            port: ctx.port,
            method: "POST",
            requestPath: "/api/login",
            headers: { "Content-Type": "text/plain" },
            body: "hello"
        });

        assert.equal(wrongType.status, 415);

        const tooLarge = await rawRequest({
            port: ctx.port,
            method: "POST",
            requestPath: "/api/login",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: "a", password: "x".repeat(10000) })
        });

        assert.equal(tooLarge.status, 413);

        const malformed = await rawRequest({
            port: ctx.port,
            method: "POST",
            requestPath: "/api/login",
            headers: { "Content-Type": "application/json" },
            body: "{ nope"
        });

        assert.equal(malformed.status, 400);

    } finally {
        await ctx.close();
    }
});

test("only whitelisted files are served and data files are never exposed", async () => {

    const ctx = await startTestServer();

    try {

        const loginPage = await rawRequest({
            port: ctx.port,
            requestPath: "/login/"
        });

        assert.equal(loginPage.status, 200);
        assert.match(loginPage.headers["content-security-policy"], /default-src 'self'/);
        assert.equal(loginPage.headers["x-content-type-options"], "nosniff");

        for (const blockedPath of [
            "/data/users.json",
            "/data/login-events.jsonl",
            "/server/start.js",
            "/package.json",
            "/js/%2e%2e/data/users.json",
            "/js/../server/server.js",
            "/js/sub/file.js"
        ]) {

            const result = await rawRequest({
                port: ctx.port,
                requestPath: blockedPath
            });

            assert.equal(result.status, 404, `${blockedPath} must not be served`);
        }

    } finally {
        await ctx.close();
    }
});

test("events endpoint validates its query parameter", async () => {

    const ctx = await startTestServer();

    try {

        const bad = await rawRequest({
            port: ctx.port,
            requestPath: "/api/events?after=abc"
        });

        assert.equal(bad.status, 400);

    } finally {
        await ctx.close();
    }
});


/* =========================================
   ANALYZER INTEGRATION
========================================= */

test("real failed logins from one IP produce a BRUTE_FORCE alert in the existing analyzer", async () => {

    const ctx = await startTestServer({ allowDevIpOverride: true });

    try {

        for (const username of ["admin", "root", "operator"]) {

            await postJson(
                ctx.baseUrl,
                "/api/login",
                { username, password: "guess guess guess" },
                { "X-Sentinel-Test-IP": "203.0.113.77" }
            );
        }

        const feed = await getEvents(ctx.baseUrl);

        const analysis = analyzeEvents(feed.events);

        assert.equal(analysis.malformedEvents, 0);
        assert.equal(analysis.failedLogins, 3);
        assert.equal(analysis.alerts.length, 1);
        assert.equal(analysis.alerts[0].type, "BRUTE_FORCE");
        assert.equal(analysis.alerts[0].sourceIp, "203.0.113.77");

    } finally {
        await ctx.close();
    }
});

test("successful logins are counted and raise no alert", async () => {

    const ctx = await startTestServer();

    try {

        await postJson(ctx.baseUrl, "/api/register", {
            username: "frank",
            password: "correct horse battery"
        });

        await postJson(ctx.baseUrl, "/api/login", {
            username: "frank",
            password: "correct horse battery"
        });

        const feed = await getEvents(ctx.baseUrl);

        const analysis = analyzeEvents(feed.events);

        assert.equal(analysis.successfulLogins, 1);
        assert.equal(analysis.alerts.length, 0);

    } finally {
        await ctx.close();
    }
});


/* =========================================
   LIVE FEED
========================================= */

test("live feed delivers the backlog, then only new events", async () => {

    const ctx = await startTestServer();

    let feed = null;

    try {

        await postJson(ctx.baseUrl, "/api/login", {
            username: "first",
            password: "whatever password"
        });

        const batches = [];
        const statuses = [];

        feed = startLiveFeed({
            endpoint: `${ctx.baseUrl}/api/events`,
            intervalMs: 100,
            onEvents: (events, details) => batches.push({ events, ...details }),
            onStatus: status => statuses.push(status.online)
        });

        await waitFor(() => batches.length >= 1);

        assert.equal(batches[0].initial, true);
        assert.equal(batches[0].events.length, 1);

        await postJson(ctx.baseUrl, "/api/login", {
            username: "second",
            password: "whatever password"
        });

        await waitFor(() => batches.length >= 2);

        assert.equal(batches[1].initial, false);
        assert.equal(batches[1].events.length, 1);
        assert.equal(batches[1].events[0].username, "second");
        assert.deepEqual(statuses, [true]);

    } finally {
        feed?.stop();
        await ctx.close();
    }
});

test("live feed reports offline when the server is unreachable", async () => {

    const statuses = [];

    const feed = startLiveFeed({
        endpoint: "http://127.0.0.1:1/api/events",
        intervalMs: 100,
        onEvents: () => assert.fail("no events expected"),
        onStatus: status => statuses.push(status.online)
    });

    try {
        await waitFor(() => statuses.length >= 1);
        assert.deepEqual(statuses, [false]);
    } finally {
        feed.stop();
    }
});

test("live feed validates its configuration", () => {

    assert.throws(() => startLiveFeed({}), TypeError);

    assert.throws(
        () => startLiveFeed({ onEvents: () => {}, intervalMs: 5 }),
        RangeError
    );
});


/**
 * Polls a condition until it is true or the timeout expires.
 */
async function waitFor(condition, timeoutMs = 3000) {

    const deadline = Date.now() + timeoutMs;

    while (!condition()) {

        if (Date.now() > deadline) {
            throw new Error("Timed out waiting for condition.");
        }

        await new Promise(resolve => setTimeout(resolve, 20));
    }
}
