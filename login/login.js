/*
 * SENTINEL PORTAL
 * Login Page Controller
 *
 * Responsible for:
 * - Switching between Sign In and Create Account
 * - Validating input before submission (the server validates again)
 * - Submitting credentials to the local Sentinel server
 * - Showing results with safe DOM updates (textContent only)
 */

const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{3,32}$/;

const PASSWORD_MIN_LENGTH = 8;

const PASSWORD_MAX_LENGTH = 128;


/* =========================================
   DOM REFERENCES
========================================= */

const loginTab = document.getElementById("tab-login");
const registerTab = document.getElementById("tab-register");

const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");

const messageElement = document.getElementById("form-message");

const loginUsername = document.getElementById("login-username");
const loginPassword = document.getElementById("login-password");

const registerUsername = document.getElementById("register-username");
const registerPassword = document.getElementById("register-password");
const registerConfirm = document.getElementById("register-confirm");


/* =========================================
   MESSAGES AND MODES
========================================= */

/**
 * Shows a status message.
 *
 * @param {string} text - Message text (rendered as plain text)
 * @param {"error"|"success"|""} kind - Message style
 */
function showMessage(text, kind = "") {

    messageElement.textContent = text;

    messageElement.className = "message";

    if (text && kind) {
        messageElement.classList.add(`message-${kind}`);
    }
}


/**
 * Switches between the sign-in and account-creation forms.
 *
 * @param {"login"|"register"} mode
 */
function setMode(mode) {

    const isLogin = mode === "login";

    loginForm.hidden = !isLogin;
    registerForm.hidden = isLogin;

    loginTab.setAttribute("aria-selected", String(isLogin));
    registerTab.setAttribute("aria-selected", String(!isLogin));

    loginTab.tabIndex = isLogin ? 0 : -1;
    registerTab.tabIndex = isLogin ? -1 : 0;

    showMessage("");

    (isLogin ? loginUsername : registerUsername).focus();
}


/* =========================================
   SERVER REQUESTS
========================================= */

/**
 * Sends a JSON POST request to the local server.
 *
 * @param {string} url - API endpoint
 * @param {Object} payload - Request body
 * @returns {Promise<{ok: boolean, status: number, data: Object|null}>}
 */
async function postJson(url, payload) {

    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    let data = null;

    try {
        data = await response.json();
    } catch {
        /* Non-JSON response; leave data as null. */
    }

    return { ok: response.ok, status: response.status, data };
}


/**
 * Runs a form submission while disabling its button.
 *
 * @param {HTMLFormElement} form
 * @param {Function} action - Async submission logic
 */
async function runSubmission(form, action) {

    const button = form.querySelector("button[type='submit']");

    button.disabled = true;

    try {
        await action();
    } catch {
        showMessage("Unable to reach the server. Please try again.", "error");
    } finally {
        button.disabled = false;
    }
}


/* =========================================
   FORM HANDLERS
========================================= */

loginForm.addEventListener("submit", event => {

    event.preventDefault();

    const username = loginUsername.value;
    const password = loginPassword.value;

    if (username.trim() === "" || password === "") {
        showMessage("Enter your username and password.", "error");
        return;
    }

    runSubmission(loginForm, async () => {

        const result = await postJson("/api/login", { username, password });

        loginPassword.value = "";

        if (result.ok) {
            showMessage(
                `Signed in as ${result.data?.username ?? username}.`,
                "success"
            );
            return;
        }

        showMessage(
            result.data?.error ?? "Sign in failed. Please try again.",
            "error"
        );
    });
});


registerForm.addEventListener("submit", event => {

    event.preventDefault();

    const username = registerUsername.value;
    const password = registerPassword.value;

    if (!USERNAME_PATTERN.test(username)) {
        showMessage(
            "Username must be 3-32 characters using letters, numbers, " +
            "dots, underscores or hyphens.",
            "error"
        );
        return;
    }

    if (
        password.length < PASSWORD_MIN_LENGTH ||
        password.length > PASSWORD_MAX_LENGTH
    ) {
        showMessage(
            `Password must be ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} characters.`,
            "error"
        );
        return;
    }

    if (password !== registerConfirm.value) {
        showMessage("Passwords do not match.", "error");
        return;
    }

    runSubmission(registerForm, async () => {

        const result = await postJson("/api/register", { username, password });

        registerPassword.value = "";
        registerConfirm.value = "";

        if (result.ok) {

            registerForm.reset();

            setMode("login");

            loginUsername.value = username;

            loginPassword.focus();

            showMessage("Account created. You can now sign in.", "success");

            return;
        }

        showMessage(
            result.data?.error ?? "Account creation failed. Please try again.",
            "error"
        );
    });
});


loginTab.addEventListener("click", () => setMode("login"));

registerTab.addEventListener("click", () => setMode("register"));


/* Arrow keys move between tabs, as expected for a tab list. */

for (const tab of [loginTab, registerTab]) {

    tab.addEventListener("keydown", event => {

        if (event.key === "ArrowLeft" || event.key === "ArrowRight") {

            const nextMode = tab === loginTab ? "register" : "login";

            setMode(nextMode);

            (nextMode === "login" ? loginTab : registerTab).focus();
        }
    });
}
