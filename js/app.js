
/*
 * SENTINEL SECURITY MONITORING DASHBOARD
 * Main Application Controller
 *
 * Responsible for:
 * - Initializing the dashboard
 * - Loading initial authentication events
 * - Connecting the security analyzer
 * - Running the event simulation
 * - Handling dashboard controls
 */


/* =========================================
   MODULE IMPORTS
========================================= */

import {
    getInitialEvents,
    generateBruteForceEvents,
    startEventSimulation,
    stopEventSimulation
} from "./events.js";

import {
    analyzeEvents
} from "./analyzer.js";

import {
    initializeDashboard,
    renderDashboard
} from "./dashboard.js";

import {
    startLiveFeed
} from "./liveFeed.js";


/* =========================================
   APPLICATION CONFIGURATION
========================================= */

const SIMULATION_INTERVAL_MS = 4000;

const MAX_STORED_EVENTS = 500;


/* =========================================
   APPLICATION STATE
========================================= */

let events = [];

let simulationInterval = null;

let liveFeed = null;

let liveMode = false;


/* =========================================
   DOM REFERENCES
========================================= */

const systemStatus = document.getElementById("system-status");

const simulationToggle = document.getElementById("simulation-toggle");

const generateAttackButton = document.getElementById("generate-attack");

const environmentBadge = document.getElementById("environment-badge");

const footerDataNote = document.getElementById("footer-data-note");


/* =========================================
   DASHBOARD DATA PROCESSING
========================================= */

/**
 * Runs the security analyzer and refreshes
 * the dashboard with the latest results.
 */
function updateDashboard() {

    const analysis = analyzeEvents(events);

    renderDashboard(events, analysis);
}


/**
 * Adds new authentication events to the application.
 *
 * @param {Array} newEvents - Events to process
 */
function addEvents(newEvents) {

    if (!Array.isArray(newEvents) || newEvents.length === 0) {
        return;
    }

    events.push(...newEvents);

    /*
     * Retain only the most recent events.
     * This prevents unlimited memory growth.
     */

    if (events.length > MAX_STORED_EVENTS) {

        events = events.slice(-MAX_STORED_EVENTS);
    }

    updateDashboard();
}


/* =========================================
   SIMULATION STATUS
========================================= */

/**
 * Updates the application status indicator.
 *
 * @param {string} status - Current simulation status
 */
function updateSystemStatus(status) {

    if (systemStatus) {
        systemStatus.textContent = status;
    }
}


/* =========================================
   START EVENT SIMULATION
========================================= */

/**
 * Starts automatic authentication event generation.
 */
function resumeSimulation() {

    if (simulationInterval !== null) {
        return;
    }

    simulationInterval = startEventSimulation(
        (event) => {
            addEvents([event]);
        },
        SIMULATION_INTERVAL_MS
    );

    simulationToggle.textContent = "Pause Simulation";

    updateSystemStatus("SIMULATION ACTIVE");

    console.log("Sentinel event simulation started.");
}


/* =========================================
   PAUSE EVENT SIMULATION
========================================= */

/**
 * Stops automatic authentication event generation.
 */
function pauseSimulation() {

    if (simulationInterval === null) {
        return;
    }

    stopEventSimulation(simulationInterval);

    simulationInterval = null;

    simulationToggle.textContent = "Resume Simulation";

    updateSystemStatus("SIMULATION PAUSED");

    console.log("Sentinel event simulation paused.");
}


/* =========================================
   SIMULATION TOGGLE
========================================= */

/**
 * Toggles event simulation on or off.
 */
function toggleSimulation() {

    if (simulationInterval !== null) {

        pauseSimulation();

    } else {

        resumeSimulation();
    }
}


/* =========================================
   BRUTE-FORCE ATTACK SIMULATION
========================================= */

/**
 * Generates a simulated brute-force attack
 * and immediately processes the resulting events.
 */
function simulateBruteForceAttack() {

    console.warn("Simulating brute-force activity.");

    const attackEvents = generateBruteForceEvents({

        attempts: 5,

        sourceIp: "203.0.113.250",

        username: "admin"

    });

    addEvents(attackEvents);

    console.log(
        `Generated ${attackEvents.length} failed login attempts.`
    );
}


/* =========================================
   LIVE LOGIN FEED
========================================= */

/**
 * Switches the dashboard from simulated data to real events
 * recorded by the Sentinel login portal.
 *
 * Simulation controls are disabled so fake events can never
 * be mixed into the real event stream.
 */
function enterLiveMode() {

    if (liveMode) {
        return;
    }

    liveMode = true;

    pauseSimulation();

    events = [];

    simulationToggle.disabled = true;
    generateAttackButton.disabled = true;
    simulationToggle.textContent = "Simulation Disabled (Live)";

    if (environmentBadge) {
        environmentBadge.textContent = "LIVE: SENTINEL LOGIN PORTAL";
    }

    if (footerDataNote) {
        footerDataNote.textContent =
            "DEVELOPMENT BUILD | LIVE PORTAL EVENTS";
    }

    updateSystemStatus("LIVE MONITORING");
}


/**
 * Receives events from the live feed.
 *
 * @param {Array} liveEvents - Validated events from the server
 * @param {{initial: boolean}} details - initial is true for the backlog
 */
function handleLiveEvents(liveEvents, { initial }) {

    enterLiveMode();

    if (initial) {
        events = [];
    }

    if (liveEvents.length > 0) {
        addEvents(liveEvents);
    } else {
        updateDashboard();
    }
}


/**
 * Reflects live feed connectivity in the status indicator.
 *
 * @param {{online: boolean}} status
 */
function handleLiveStatus({ online }) {

    if (!liveMode) {
        return;
    }

    updateSystemStatus(online ? "LIVE MONITORING" : "LIVE FEED DISCONNECTED");
}


/* =========================================
   APPLICATION INITIALIZATION
========================================= */

/**
 * Initializes Sentinel and starts monitoring.
 */
function initializeApplication() {

    try {

        if (!simulationToggle || !generateAttackButton) {
            throw new Error("Required dashboard controls were not found.");
        }

        if (!systemStatus) {
            throw new Error("System status element was not found.");
        }


        /* Initialize dashboard controls */

        initializeDashboard();


        /* Load initial sample authentication events */

        events = getInitialEvents();


        /* Process and display initial security analysis */

        updateDashboard();


        /* Connect simulation controls */

        simulationToggle.addEventListener(
            "click",
            toggleSimulation
        );

        generateAttackButton.addEventListener(
            "click",
            simulateBruteForceAttack
        );


        /* Start automatic event generation */

        resumeSimulation();


        /*
         * Connect to the Sentinel login portal server.
         * If it is unreachable, the simulation keeps running.
         */

        liveFeed = startLiveFeed({
            onEvents: handleLiveEvents,
            onStatus: handleLiveStatus
        });


        console.log("Sentinel initialized successfully.");

    } catch (error) {

        updateSystemStatus("INITIALIZATION ERROR");

        console.error(
            "Sentinel initialization failed:",
            error
        );

    }
}


/* =========================================
   START APPLICATION
========================================= */

initializeApplication();
