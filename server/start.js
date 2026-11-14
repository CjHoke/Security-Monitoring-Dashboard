/*
 * SENTINEL LOGIN PORTAL
 * Server Entry Point
 *
 * Usage:   npm start
 * Options (environment variables):
 *   SENTINEL_PORT             Port to listen on (default 3000)
 *   SENTINEL_DEV_IP_OVERRIDE  Set to 1 to let local test scripts simulate
 *                             source IPs via the X-Sentinel-Test-IP header.
 *                             Development only; leave unset normally.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import { createSentinelServer } from "./server.js";

const projectRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    ".."
);

const requestedPort = Number.parseInt(
    process.env.SENTINEL_PORT ?? "3000",
    10
);

if (
    !Number.isInteger(requestedPort) ||
    requestedPort < 1 ||
    requestedPort > 65535
) {
    console.error("SENTINEL_PORT must be an integer between 1 and 65535.");
    process.exit(1);
}

const allowDevIpOverride = process.env.SENTINEL_DEV_IP_OVERRIDE === "1";

try {

    const app = await createSentinelServer({
        projectRoot,
        port: requestedPort,
        allowDevIpOverride
    });

    const { host, port } = await app.start();

    console.log("Sentinel is running (local access only).");
    console.log(`  Login portal: http://${host}:${port}/login/`);
    console.log(`  Dashboard:    http://${host}:${port}/`);

    if (allowDevIpOverride) {
        console.warn(
            "WARNING: dev IP override is ON. Test scripts can spoof " +
            "source IPs. Do not use this mode for real monitoring."
        );
    }

    const shutdown = async () => {
        await app.stop();
        process.exit(0);
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);

} catch (error) {

    console.error("Sentinel failed to start:", error.message);
    process.exit(1);
}
