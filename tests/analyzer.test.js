
/*
 * SENTINEL SECURITY MONITORING DASHBOARD
 * Analyzer Unit Tests
 *
 * Tests:
 * - Authentication event statistics
 * - Brute-force detection
 * - Sliding time-window behavior
 * - IP address isolation
 * - Malformed event handling
 * - Custom detection thresholds
 * - Invalid configuration handling
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
    analyzeEvents,
    DEFAULT_DETECTION_THRESHOLD,
    DEFAULT_DETECTION_WINDOW_MS
} from "../js/analyzer.js";


/* =========================================
   TEST HELPERS
========================================= */

const BASE_TIME = Date.UTC(2026, 0, 1, 0, 0, 0);


/**
 * Creates a test authentication event.
 *
 * @param {string} type - Event type
 * @param {string} sourceIp - Source IP address
 * @param {number} secondsAfterBase - Event time offset
 * @param {string} username - Account username
 * @returns {Object}
 */
function createTestEvent(
    type,
    sourceIp,
    secondsAfterBase,
    username = "admin"
) {

    return {
        id: `test-${secondsAfterBase}-${sourceIp}`,
        timestamp: new Date(
            BASE_TIME + secondsAfterBase * 1000
        ).toISOString(),
        sourceIp,
        username,
        type,
        status: type === "FAILED_LOGIN" ? "FAILED" : "SUCCESS"
    };
}


/* =========================================
   TEST 1: DEFAULT CONFIGURATION
========================================= */

test("Default detection configuration is correct", () => {

    assert.equal(DEFAULT_DETECTION_THRESHOLD, 3);

    assert.equal(
        DEFAULT_DETECTION_WINDOW_MS,
        5 * 60 * 1000
    );

});


/* =========================================
   TEST 2: EVENT STATISTICS
========================================= */

test("Analyzer correctly calculates authentication statistics", () => {

    const events = [

        createTestEvent("SUCCESS_LOGIN", "192.0.2.10", 0),

        createTestEvent("FAILED_LOGIN", "192.0.2.15", 10),

        createTestEvent("FAILED_LOGIN", "198.51.100.10", 20),

        createTestEvent("SUCCESS_LOGIN", "192.0.2.20", 30),

        createTestEvent("FAILED_LOGIN", "203.0.113.10", 40)

    ];

    const result = analyzeEvents(events);

    assert.equal(result.totalEvents, 5);

    assert.equal(result.failedLogins, 3);

    assert.equal(result.successfulLogins, 2);

    assert.equal(result.suspiciousIps, 0);

    assert.equal(result.malformedEvents, 0);

});


/* =========================================
   TEST 3: BRUTE-FORCE DETECTION
========================================= */

test("Detects three failed logins from one IP within five minutes", () => {

    const events = [

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 0),

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 30),

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 60)

    ];

    const result = analyzeEvents(events);

    assert.equal(result.suspiciousIps, 1);

    assert.equal(result.alerts.length, 1);

    assert.equal(
        result.alerts[0].sourceIp,
        "203.0.113.42"
    );

    assert.equal(
        result.alerts[0].attemptCount,
        3
    );

    assert.equal(
        result.alerts[0].severity,
        "HIGH"
    );

});


/* =========================================
   TEST 4: SLIDING TIME WINDOW
========================================= */

test("Does not flag three failures spread across more than five minutes", () => {

    const events = [

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 0),

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 180),

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 360)

    ];

    const result = analyzeEvents(events);

    assert.equal(result.suspiciousIps, 0);

    assert.equal(result.alerts.length, 0);

});


/* =========================================
   TEST 5: IP ADDRESS ISOLATION
========================================= */

test("Does not combine failed logins from different IP addresses", () => {

    const events = [

        createTestEvent("FAILED_LOGIN", "203.0.113.10", 0),

        createTestEvent("FAILED_LOGIN", "203.0.113.10", 30),

        createTestEvent("FAILED_LOGIN", "203.0.113.20", 10),

        createTestEvent("FAILED_LOGIN", "203.0.113.20", 40)

    ];

    const result = analyzeEvents(events);

    assert.equal(result.failedLogins, 4);

    assert.equal(result.suspiciousIps, 0);

});


/* =========================================
   TEST 6: MULTIPLE SUSPICIOUS IP ADDRESSES
========================================= */

test("Detects multiple suspicious IP addresses independently", () => {

    const events = [

        createTestEvent("FAILED_LOGIN", "203.0.113.10", 0),

        createTestEvent("FAILED_LOGIN", "203.0.113.10", 10),

        createTestEvent("FAILED_LOGIN", "203.0.113.10", 20),

        createTestEvent("FAILED_LOGIN", "198.51.100.10", 30),

        createTestEvent("FAILED_LOGIN", "198.51.100.10", 40),

        createTestEvent("FAILED_LOGIN", "198.51.100.10", 50)

    ];

    const result = analyzeEvents(events);

    assert.equal(result.suspiciousIps, 2);

    assert.deepEqual(
        result.suspiciousIpAddresses.sort(),
        ["198.51.100.10", "203.0.113.10"]
    );

});


/* =========================================
   TEST 7: MALFORMED EVENTS
========================================= */

test("Ignores malformed events without crashing", () => {

    const events = [

        createTestEvent("SUCCESS_LOGIN", "192.0.2.10", 0),

        {
            sourceIp: "",
            timestamp: new Date(BASE_TIME).toISOString(),
            type: "FAILED_LOGIN"
        },

        {
            sourceIp: "203.0.113.10",
            timestamp: "invalid-date",
            type: "FAILED_LOGIN"
        },

        {
            sourceIp: "203.0.113.20",
            timestamp: new Date(BASE_TIME).toISOString(),
            type: "UNKNOWN_EVENT"
        }

    ];

    const result = analyzeEvents(events);

    assert.equal(result.totalEvents, 1);

    assert.equal(result.malformedEvents, 3);

    assert.equal(result.successfulLogins, 1);

});


/* =========================================
   TEST 8: CUSTOM DETECTION THRESHOLD
========================================= */

test("Supports a custom brute-force detection threshold", () => {

    const events = [

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 0),

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 10),

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 20),

        createTestEvent("FAILED_LOGIN", "203.0.113.42", 30)

    ];

    const result = analyzeEvents(events, {
        threshold: 4,
        windowMs: 5 * 60 * 1000
    });

    assert.equal(result.suspiciousIps, 1);

    assert.equal(result.alerts[0].threshold, 4);

    assert.equal(result.alerts[0].attemptCount, 4);

});


/* =========================================
   TEST 9: INVALID INPUT COLLECTION
========================================= */

test("Rejects non-array event collections", () => {

    assert.throws(
        () => analyzeEvents(null),
        TypeError
    );

});


/* =========================================
   TEST 10: INVALID DETECTION CONFIGURATION
========================================= */

test("Rejects invalid detection thresholds", () => {

    const events = [];

    assert.throws(
        () => analyzeEvents(events, { threshold: 1 }),
        RangeError
    );

});


/* =========================================
   TEST 11: INVALID TIME WINDOW
========================================= */

test("Rejects invalid detection time windows", () => {

    const events = [];

    assert.throws(
        () => analyzeEvents(events, { windowMs: 0 }),
        RangeError
    );

});
