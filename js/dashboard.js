
/*
 * SENTINEL SECURITY MONITORING DASHBOARD
 * Dashboard Interface Manager
 *
 * Responsible for:
 * - Updating security metrics
 * - Rendering authentication events
 * - Searching and filtering events
 * - Displaying security alerts
 * - Updating application status
 */

let currentEvents = [];
let currentAnalysis = null;

let dashboardInitialized = false;

const MAX_DISPLAYED_EVENTS = 100;
// Tracks security alerts reviewed by the analyst.
const acknowledgedAlertIds = new Set();

/* =========================================
   DOM UTILITIES
========================================= */

/**
 * Updates the text content of an HTML element.
 *
 * @param {string} elementId - Target element ID
 * @param {string|number} value - New text value
 */
function setText(elementId, value) {

    const element = document.getElementById(elementId);

    if (element) {
        element.textContent = String(value);
    }
}


/**
 * Creates a status badge without inserting HTML strings.
 *
 * @param {string} text - Badge text
 * @param {string} className - CSS class
 * @returns {HTMLElement}
 */
function createBadge(text, className) {

    const badge = document.createElement("span");

    badge.className = className;
    badge.textContent = text;

    return badge;
}


/**
 * Formats an ISO timestamp for display.
 *
 * @param {string} timestamp - ISO timestamp
 * @returns {string}
 */
function formatTimestamp(timestamp) {

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return "Unknown";
    }

    return date.toLocaleString();
}


/* =========================================
   DASHBOARD INITIALIZATION
========================================= */

/**
 * Registers dashboard search and filter listeners.
 * Should only be called once.
 */
export function initializeDashboard() {

    if (dashboardInitialized) {
        return;
    }

    const searchInput = document.getElementById("event-search");

    const eventFilter = document.getElementById("event-type-filter");

    if (!searchInput || !eventFilter) {
        console.error("Dashboard controls could not be initialized.");
        return;
    }

    searchInput.addEventListener("input", () => {
        renderEventTable();
    });

    eventFilter.addEventListener("change", () => {
        renderEventTable();
    });

    dashboardInitialized = true;

    console.log("Sentinel dashboard initialized.");
}


/* =========================================
   MAIN DASHBOARD RENDERING
========================================= */

/**
 * Updates all dashboard components.
 *
 * @param {Array} events - Authentication events
 * @param {Object} analysis - Security analysis results
 */
export function renderDashboard(events, analysis) {

    if (!Array.isArray(events)) {
        throw new TypeError("Dashboard events must be an array.");
    }

    if (!analysis || typeof analysis !== "object") {
        throw new TypeError("Valid security analysis is required.");
    }

    currentEvents = [...events];

    currentAnalysis = analysis;

    updateMetrics();

    renderEventTable();

    // Refresh security alerts whenever the dashboard updates.
    renderAlerts();
}
/**
 * Renders security alerts returned by the analyzer.
 * Preserves alert acknowledgment status between updates.
 */
function renderAlerts() {

    const alertContainer = document.getElementById("alert-list");

    if (!alertContainer) {
        console.error("Security alert container not found.");
        return;
    }

    alertContainer.replaceChildren();

    const alerts = currentAnalysis?.alerts ?? [];

    setText("alerts-count", `${alerts.length} ALERTS`);

    if (alerts.length === 0) {

        const emptyMessage = document.createElement("div");

        emptyMessage.className = "empty-alert";
        emptyMessage.textContent = "No suspicious activity detected.";

        alertContainer.appendChild(emptyMessage);

        return;
    }

    for (const alert of alerts) {

        const acknowledged = acknowledgedAlertIds.has(alert.id);

        const isCritical =
            alert.severity === "HIGH" ||
            alert.severity === "CRITICAL";

        /* Alert container */

        const alertElement = document.createElement("article");

        alertElement.className =
            `alert-item ${isCritical ? "alert-critical" : "alert-warning"}`;

        if (acknowledged) {
            alertElement.classList.add("alert-acknowledged");
        }

        /* Alert header */

        const header = document.createElement("div");

        header.className = "alert-header";

        const title = document.createElement("h4");

        title.className = "alert-title";
        title.textContent = alert.title;

        const severity = document.createElement("span");

        severity.className = "alert-severity";
        severity.textContent = alert.severity;

        header.append(title, severity);

        /* Alert description */

        const description = document.createElement("p");

        description.className = "alert-description";
        description.textContent = alert.description;

        /* Alert metadata */

        const metadata = document.createElement("div");

        metadata.className = "alert-metadata";

        const windowMinutes = alert.windowMs / 60000;

        metadata.textContent =
            `IP: ${alert.sourceIp} | ` +
            `Attempts: ${alert.attemptCount} | ` +
            `Window: ${windowMinutes} min`;

        /* Acknowledgment controls */

        const actions = document.createElement("div");

        actions.className = "alert-actions";

        const acknowledgmentStatus = document.createElement("span");

        acknowledgmentStatus.className = "acknowledgment-status";

        acknowledgmentStatus.textContent = acknowledged
            ? "ACKNOWLEDGED"
            : "REQUIRES REVIEW";

        const acknowledgeButton = document.createElement("button");

        acknowledgeButton.type = "button";

        acknowledgeButton.className = "acknowledge-button";

        acknowledgeButton.textContent = acknowledged
            ? "Acknowledged"
            : "Acknowledge Alert";

        acknowledgeButton.disabled = acknowledged;

        acknowledgeButton.setAttribute(
            "aria-label",
            `Acknowledge alert from ${alert.sourceIp}`
        );

        acknowledgeButton.addEventListener("click", () => {

            acknowledgedAlertIds.add(alert.id);

            renderAlerts();

        });

        actions.append(
            acknowledgmentStatus,
            acknowledgeButton
        );

        /* Assemble alert */

        alertElement.append(
            header,
            description,
            metadata,
            actions
        );

        alertContainer.appendChild(alertElement);
    }
}



/* =========================================
   SECURITY METRICS
========================================= */

/**
 * Updates the four dashboard metric cards.
 */
function updateMetrics() {

    if (!currentAnalysis) {
        return;
    }

    setText(
        "metric-total-events",
        currentAnalysis.totalEvents ?? 0
    );

    setText(
        "metric-failed-logins",
        currentAnalysis.failedLogins ?? 0
    );

    setText(
        "metric-successful-logins",
        currentAnalysis.successfulLogins ?? 0
    );

    setText(
        "metric-suspicious-ips",
        currentAnalysis.suspiciousIps ?? 0
    );
}


/* =========================================
   EVENT SEARCH AND FILTERING
========================================= */

/**
 * Returns events matching the current search
 * and event type filter.
 *
 * @returns {Array}
 */
function getFilteredEvents() {

    const searchInput = document.getElementById("event-search");

    const eventFilter = document.getElementById("event-type-filter");

    const searchTerm = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";

    const selectedType = eventFilter
        ? eventFilter.value
        : "ALL";

    return currentEvents.filter(event => {

        const matchesSearch =
            event.sourceIp.toLowerCase().includes(searchTerm) ||
            event.username.toLowerCase().includes(searchTerm) ||
            event.type.toLowerCase().includes(searchTerm);

        const matchesType =
            selectedType === "ALL" ||
            event.type === selectedType;

        return matchesSearch && matchesType;

    });
}


/* =========================================
   AUTHENTICATION EVENT TABLE
========================================= */

/**
 * Renders the authentication event table.
 */
function renderEventTable() {

    const tableBody = document.getElementById("event-table-body");

    if (!tableBody) {
        console.error("Authentication event table not found.");
        return;
    }

    tableBody.replaceChildren();

    const filteredEvents = getFilteredEvents();

    /*
     * Display newest events first.
     */

    const sortedEvents = [...filteredEvents].sort(
        (a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)
    );

    const displayedEvents = sortedEvents.slice(
        0,
        MAX_DISPLAYED_EVENTS
    );

    if (displayedEvents.length === 0) {

        const row = document.createElement("tr");

        const cell = document.createElement("td");

        cell.colSpan = 5;

        cell.className = "empty-table";

        cell.textContent = "No matching authentication events found.";

        row.appendChild(cell);

        tableBody.appendChild(row);
    }

    for (const event of displayedEvents) {

        const row = document.createElement("tr");

        /* Timestamp */

        const timestampCell = document.createElement("td");

        const timeElement = document.createElement("time");

        timeElement.dateTime = event.timestamp;

        timeElement.textContent = formatTimestamp(event.timestamp);

        timestampCell.appendChild(timeElement);


        /* Source IP */

        const ipCell = document.createElement("td");

        ipCell.textContent = event.sourceIp;


        /* Username */

        const usernameCell = document.createElement("td");

        usernameCell.textContent = event.username;


        /* Event type */

        const typeCell = document.createElement("td");

        const isFailed = event.type === "FAILED_LOGIN";

        typeCell.appendChild(
            createBadge(
                isFailed ? "FAILED LOGIN" : "SUCCESS LOGIN",
                `event-type ${isFailed ? "status-failed" : "status-success"}`
            )
        );


        /* Authentication status */

        const statusCell = document.createElement("td");

        statusCell.appendChild(
            createBadge(
                event.status,
                `status-badge ${isFailed ? "status-failed" : "status-success"}`
            )
        );


        /* Add cells to row */

        row.append(
            timestampCell,
            ipCell,
            usernameCell,
            typeCell,
            statusCell
        );

        tableBody.appendChild(row);
    }


    /* Update event counter */

    const countText = sortedEvents.length > MAX_DISPLAYED_EVENTS
        ? `${displayedEvents.length} / ${sortedEvents.length} EVENTS`
        : `${sortedEvents.length} EVENTS`;

    setText("events-count", countText);
}


/* =========================================
   SECURITY ALERTS
========================================= */

/**
 * Renders security alerts returned by the analyzer.
 */


