/*
 * SENTINEL LOGIN PORTAL
 * Local HTTP Server
 *
 * Responsible for:
 * - Serving the login portal and the Sentinel dashboard (whitelisted files only)
 * - Handling account creation and login
 * - Recording every login attempt as a Sentinel authentication event
 * - Exposing recorded events to the dashboard
 *
 * Security model:
 * - Binds to loopback only unless explicitly overridden
 * - Rejects unexpected Host headers (DNS rebinding defense)
 * - Rejects cross-origin POST requests
 * - Static files come from an explicit whitelist, never a user path
 * - Request bodies are size limited and strictly validated
 * - Responses never reveal whether a username exists
 */

import http from "node:http";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";

import { UserStore } from "./userStore.js";
import { EventLog } from "./eventLog.js";
import { LockoutTracker, SlidingWindowLimiter } from "./lockout.js";

import {
    hashPassword,
    verifyPassword,
    verifyAgainstDummyHash
} from "./passwords.js";

import {
    USERNAME_PATTERN,
    PASSWORD_MAX_LENGTH,
    validateRegistration,
    sanitizeLoggedUsername,
    normalizeRemoteAddress,
    isLoopbackAddress
} from "./validation.js";


const JSON_BODY_LIMIT_BYTES = 4096;

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

const DEV_IP_HEADER = "x-sentinel-test-ip";

const CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8"
};

/*
 * The only static files that can ever be served.
 * Dynamic matches below are limited to js/<name>.js.
 */

const STATIC_FILES = new Map([
    ["/", "index.html"],
    ["/style.css", "style.css"],
    ["/login/", "login/index.html"],
    ["/login/login.css", "login/login.css"],
    ["/login/login.js", "login/login.js"]
]);

const DASHBOARD_MODULE_PATTERN = /^\/js\/[A-Za-z0-9_-]+\.js$/;

const SECURITY_HEADERS = {
    "Content-Security-Policy":
        "default-src 'self'; script-src 'self'; style-src 'self'; " +
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; " +
        "form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin"
};


class HttpError extends Error {

    constructor(status, message) {
        super(message);
        this.status = status;
    }
}


/**
 * Sends a JSON response.
 */
function sendJson(response, status, body, extraHeaders = {}) {

    const payload = JSON.stringify(body);

    response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(payload),
        "Cache-Control": "no-store",
        ...extraHeaders
    });

    response.end(payload);
}


/**
 * Reads and parses a size-limited JSON request body.
 *
 * @param {http.IncomingMessage} request
 * @returns {Promise<Object>} Parsed plain object
 */
function readJsonBody(request) {

    return new Promise((resolve, reject) => {

        const contentType = request.headers["content-type"] ?? "";

        if (!/^application\/json\s*(;|$)/i.test(contentType)) {
            request.resume();
            reject(new HttpError(415, "Content-Type must be application/json."));
            return;
        }

        const chunks = [];
        let receivedBytes = 0;
        let settled = false;

        request.on("data", chunk => {

            if (settled) {
                return;
            }

            receivedBytes += chunk.length;

            if (receivedBytes > JSON_BODY_LIMIT_BYTES) {
                settled = true;
                reject(new HttpError(413, "Request body too large."));
                request.resume();
                return;
            }

            chunks.push(chunk);
        });

        request.on("end", () => {

            if (settled) {
                return;
            }

            settled = true;

            try {

                const parsed = JSON.parse(
                    Buffer.concat(chunks).toString("utf8")
                );

                if (
                    parsed === null ||
                    typeof parsed !== "object" ||
                    Array.isArray(parsed)
                ) {
                    throw new Error("Body must be an object.");
                }

                resolve(parsed);

            } catch {
                reject(new HttpError(400, "Malformed JSON body."));
            }
        });

        request.on("error", () => {

            if (!settled) {
                settled = true;
                reject(new HttpError(400, "Request could not be read."));
            }
        });
    });
}


/**
 * Creates the Sentinel login portal server.
 *
 * @param {Object} options
 * @param {string} options.projectRoot - Project folder containing index.html
 * @param {string} [options.usersFile] - Account store path
 * @param {string} [options.eventsFile] - Event log path
 * @param {string} [options.host] - Bind address (loopback by default)
 * @param {number} [options.port] - Port (0 chooses a free port)
 * @param {boolean} [options.allowDevIpOverride] - Honor X-Sentinel-Test-IP
 * @param {boolean} [options.allowNonLoopbackBind] - Permit non-loopback host
 * @param {Object} [options.lockoutOptions] - LockoutTracker settings
 * @param {Object} [options.registrationLimit] - Account creation limit
 * @returns {Promise<Object>} Server controller
 */
export async function createSentinelServer(options = {}) {

    const {
        projectRoot,
        host = "127.0.0.1",
        port = 3000,
        allowDevIpOverride = false,
        allowNonLoopbackBind = false,
        lockoutOptions = {},
        registrationLimit = { limit: 5, windowMs: 60 * 60 * 1000 }
    } = options;

    if (typeof projectRoot !== "string" || projectRoot === "") {
        throw new TypeError("projectRoot is required.");
    }

    if (!LOOPBACK_HOSTS.has(host) && !allowNonLoopbackBind) {
        throw new Error(
            `Refusing to bind to non-loopback host "${host}". ` +
            "Sentinel is local-only by default."
        );
    }

    const usersFile = options.usersFile ??
        path.join(projectRoot, "data", "users.json");

    const eventsFile = options.eventsFile ??
        path.join(projectRoot, "data", "login-events.jsonl");

    const userStore = new UserStore(usersFile);
    const eventLog = new EventLog(eventsFile);
    const lockoutTracker = new LockoutTracker(lockoutOptions);
    const registrationLimiter = new SlidingWindowLimiter(registrationLimit);

    await userStore.load();
    await eventLog.load();

    const server = http.createServer((request, response) => {

        handleRequest(request, response).catch(error => {

            if (error instanceof HttpError) {

                if (!response.headersSent) {
                    sendJson(
                        response,
                        error.status,
                        { error: error.message },
                        error.status === 413 ? { Connection: "close" } : {}
                    );
                }

                return;
            }

            /* Log the error type only; never request contents. */

            console.error("Request failed:", error.name, error.code ?? "");

            if (!response.headersSent) {
                sendJson(response, 500, { error: "Internal server error." });
            }
        });
    });

    server.headersTimeout = 10000;
    server.requestTimeout = 15000;


    /* ----- request helpers ----- */

    function currentPort() {
        return server.address()?.port ?? port;
    }

    function allowedHostHeaders() {

        const activePort = currentPort();

        return new Set([
            `127.0.0.1:${activePort}`,
            `localhost:${activePort}`,
            `[::1]:${activePort}`
        ]);
    }

    function isAllowedOrigin(request) {

        const origin = request.headers.origin;

        if (origin === undefined) {
            return true;
        }

        const hosts = allowedHostHeaders();

        return typeof origin === "string" &&
            [...hosts].some(allowedHost => origin === `http://${allowedHost}`);
    }

    function getClientIp(request) {

        const socketIp = normalizeRemoteAddress(request.socket.remoteAddress);

        if (allowDevIpOverride && isLoopbackAddress(socketIp)) {

            const override = request.headers[DEV_IP_HEADER];

            if (typeof override === "string" && net.isIP(override.trim())) {
                return override.trim();
            }
        }

        return socketIp;
    }

    /**
     * Records an event. A logging failure must never block the user
     * flow, so failures are reported without request details.
     */
    async function recordEvent(details) {

        try {
            return await eventLog.append(details);
        } catch (error) {
            console.error("Event logging failed:", error.name, error.code ?? "");
            return null;
        }
    }


    /* ----- route handlers ----- */

    async function handleRegister(request, response) {

        const clientIp = getClientIp(request);

        if (!registrationLimiter.tryConsume(clientIp)) {
            sendJson(response, 429, {
                error: "Too many accounts created. Try again later."
            });
            return;
        }

        const body = await readJsonBody(request);

        const validation = validateRegistration(body.username, body.password);

        if (!validation.valid) {
            sendJson(response, 400, { error: validation.error });
            return;
        }

        const passwordHash = await hashPassword(body.password);

        try {
            await userStore.create(body.username, passwordHash);
        } catch (error) {

            if (error.code === "USERNAME_TAKEN") {
                sendJson(response, 409, { error: "Username is not available." });
                return;
            }

            if (error.code === "USER_LIMIT") {
                sendJson(response, 503, {
                    error: "Account creation is currently unavailable."
                });
                return;
            }

            throw error;
        }

        sendJson(response, 201, { ok: true, username: body.username });
    }


    async function handleLogin(request, response) {

        const clientIp = getClientIp(request);

        const body = await readJsonBody(request);

        if (
            typeof body.username !== "string" ||
            typeof body.password !== "string" ||
            body.username.trim() === "" ||
            body.password === ""
        ) {
            throw new HttpError(400, "Username and password are required.");
        }

        const loggedUsername = sanitizeLoggedUsername(body.username);

        const lockKey = loggedUsername.toLowerCase();


        /* Locked accounts: log the attempt, never verify the password. */

        const lockState = lockoutTracker.getLockState(lockKey);

        if (lockState.locked) {

            await recordEvent({
                type: "FAILED_LOGIN",
                sourceIp: clientIp,
                username: loggedUsername,
                reason: "ACCOUNT_LOCKED"
            });

            const retryAfterSeconds = Math.ceil(lockState.retryAfterMs / 1000);

            sendJson(
                response,
                429,
                {
                    error: "Too many failed attempts. Try again later.",
                    retryAfterSeconds
                },
                { "Retry-After": String(retryAfterSeconds) }
            );

            return;
        }


        /* Verify credentials (equal work for unknown usernames). */

        const account = USERNAME_PATTERN.test(body.username)
            ? userStore.get(body.username)
            : undefined;

        let authenticated = false;

        if (body.password.length <= PASSWORD_MAX_LENGTH) {

            authenticated = account
                ? await verifyPassword(body.password, account.passwordHash)
                : await verifyAgainstDummyHash(body.password);
        }


        if (authenticated) {

            lockoutTracker.recordSuccess(lockKey);

            await recordEvent({
                type: "SUCCESS_LOGIN",
                sourceIp: clientIp,
                username: account.username,
                reason: "AUTHENTICATED"
            });

            sendJson(response, 200, { ok: true, username: account.username });
            return;
        }

        lockoutTracker.recordFailure(lockKey);

        await recordEvent({
            type: "FAILED_LOGIN",
            sourceIp: clientIp,
            username: loggedUsername,
            reason: "BAD_CREDENTIALS"
        });

        sendJson(response, 401, { error: "Invalid username or password." });
    }


    function handleEvents(url, response) {

        const afterParameter = url.searchParams.get("after");

        let after = null;

        if (afterParameter !== null) {

            if (!/^\d{1,15}$/.test(afterParameter)) {
                throw new HttpError(400, "Invalid 'after' parameter.");
            }

            after = Number(afterParameter);
        }

        sendJson(response, 200, {
            events: eventLog.getEvents({ after }),
            latestSeq: eventLog.latestSeq,
            serverTime: new Date().toISOString()
        });
    }


    async function serveStatic(request, response, relativePath) {

        let content;

        try {
            content = await fs.readFile(path.join(projectRoot, relativePath));
        } catch {
            throw new HttpError(404, "Not found.");
        }

        response.writeHead(200, {
            "Content-Type":
                CONTENT_TYPES[path.extname(relativePath)] ??
                "application/octet-stream",
            "Content-Length": content.length,
            "Cache-Control": "no-store"
        });

        response.end(request.method === "HEAD" ? undefined : content);
    }


    /* ----- router ----- */

    async function handleRequest(request, response) {

        for (const [headerName, headerValue] of Object.entries(SECURITY_HEADERS)) {
            response.setHeader(headerName, headerValue);
        }

        const hostHeader = (request.headers.host ?? "").toLowerCase();

        if (!allowedHostHeaders().has(hostHeader)) {
            throw new HttpError(400, "Invalid Host header.");
        }

        let url;

        try {
            url = new URL(request.url, "http://localhost");
        } catch {
            throw new HttpError(400, "Malformed request URL.");
        }

        const { pathname } = url;

        if (pathname === "/login") {
            response.writeHead(301, { Location: "/login/" });
            response.end();
            return;
        }

        if (pathname === "/api/register" || pathname === "/api/login") {

            if (request.method !== "POST") {
                response.setHeader("Allow", "POST");
                throw new HttpError(405, "Method not allowed.");
            }

            if (!isAllowedOrigin(request)) {
                throw new HttpError(403, "Cross-origin requests are not allowed.");
            }

            if (pathname === "/api/register") {
                await handleRegister(request, response);
            } else {
                await handleLogin(request, response);
            }

            return;
        }

        if (pathname === "/api/events") {

            if (request.method !== "GET") {
                response.setHeader("Allow", "GET");
                throw new HttpError(405, "Method not allowed.");
            }

            handleEvents(url, response);
            return;
        }

        const staticFile = STATIC_FILES.get(pathname) ??
            (DASHBOARD_MODULE_PATTERN.test(pathname)
                ? pathname.slice(1)
                : null);

        if (staticFile && (request.method === "GET" || request.method === "HEAD")) {
            await serveStatic(request, response, staticFile);
            return;
        }

        throw new HttpError(staticFile ? 405 : 404, "Not found.");
    }


    /* ----- lifecycle ----- */

    return {

        server,
        userStore,
        eventLog,

        /** @returns {Promise<{host: string, port: number}>} */
        start() {

            return new Promise((resolve, reject) => {

                server.once("error", reject);

                server.listen(port, host, () => {
                    server.off("error", reject);
                    resolve({ host, port: currentPort() });
                });
            });
        },

        /** @returns {Promise<void>} */
        stop() {

            return new Promise(resolve => {
                server.close(() => resolve());
                server.closeAllConnections?.();
            });
        }
    };
}
