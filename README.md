# Sentinel — Security Monitoring Dashboard

A locally hosted security monitoring and threat detection dashboard built with JavaScript, Node.js, HTML, and CSS.

Sentinel provides a centralized interface for monitoring authentication activity, identifying suspicious login behavior, detecting potential brute-force attacks, and reviewing security events in real time.

The application includes a user authentication system, allowing users to create accounts, log in, and access the monitoring dashboard through a locally hosted server.

---

## Features

### Security Monitoring
- Real-time authentication event monitoring.
- Live security event feed.
- Successful and failed login tracking.
- Authentication statistics and activity summaries.
- Suspicious IP address identification.
- Brute-force login attempt detection.
- Configurable detection thresholds.
- Security alerts with acknowledgment controls.
- Search and filtering of authentication events.

### User Authentication
- Dedicated login interface.
- User account creation.
- Password-based authentication.
- Server-side authentication and validation.
- Account and user data persistence.
- Login activity logging.
- Account lockout functionality.

### Windows Security Event Integration
- PowerShell utility for exporting Windows Security Event Logs.
- Support for Windows Event IDs:
  - `4624` — Successful logon.
  - `4625` — Failed logon.
- Normalization of Windows authentication events for analysis.

### Security Analysis
- Detection of repeated failed authentication attempts.
- Five-minute sliding-window brute-force detection.
- IP-specific event analysis.
- Malformed event handling.
- Automated security alert generation.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| HTML5 | Application structure |
| CSS3 | Dashboard and login interface |
| JavaScript | Frontend functionality and analysis |
| Node.js | Backend server |
| npm | Package and script management |
| PowerShell | Windows Security Event collection |
| JSON | Event and user data storage |
| Node.js Test Runner | Automated testing |

---

## Project Structure

```text
Security-Monitoring-Dashboard/
│
├── index.html
├── style.css
├── package.json
├── README.md
│
├── login/
│   ├── index.html
│   ├── login.css
│   └── login.js
│
├── js/
│   ├── analyzer.js
│   ├── app.js
│   ├── dashboard.js
│   ├── events.js
│   └── liveFeed.js
│
├── server/
│   ├── eventLog.js
│   ├── lockout.js
│   ├── passwords.js
│   ├── server.js
│   ├── start.js
│   ├── userStore.js
│   └── validation.js
│
├── tests/
│   ├── analyzer.test.js
│   └── login-server.test.js
│
├── tools/
│   └── export-windows-security-events.ps1
│
└── data/
    └── sample-logs.json
    └── login-events.json
    └── users.jsoon
```

---

## Installation and Setup

### Requirements

- [Node.js](https://nodejs.org/)
- npm (included with Node.js)
- Windows (required for the Windows Security Event export utility)

### 1. Clone the Repository

```bash
git clone https://github.com/CjHoke/Security-Monitoring-Dashboard.git
```

### 2. Navigate to the Project

```bash
cd Security-Monitoring-Dashboard
```

### 3. Install Dependencies

```bash
npm install
```

### 4. View Available npm Scripts

```bash
npm run
```

### 5. Start Sentinel

```bash
npm start
```

Once the server starts, open the local address displayed in your terminal using your web browser.

Create an account through the login interface or log in with an existing account to access the monitoring dashboard.

---

## Testing

Sentinel includes automated tests using the built-in Node.js test runner.

Run the test suite with:

```bash
npm test
```

The tests cover security analysis functionality, authentication event processing, detection thresholds, and server-side login behavior.

---

## Windows Security Event Collection

Sentinel includes a PowerShell utility for collecting Windows authentication events.

Run PowerShell from the project directory:

```powershell
.\tools\export-windows-security-events.ps1
```

The script collects Windows Security Event IDs `4624` and `4625` and exports normalized event data for analysis.

Additional collection parameters can be supplied:

```powershell
.\tools\export-windows-security-events.ps1 -HoursBack 72 -MaxEvents 5000
```

Administrator privileges may be required to access the Windows Security event log.

---

## Security Considerations

Sentinel is designed as a locally hosted security monitoring project.

- Do not expose the development server directly to the public internet.
- Keep user databases, authentication logs, and real security event exports out of public repositories.
- Never commit passwords, secrets, or environment files.
- Use appropriate access controls when running the application.
- Treat collected security logs as potentially sensitive information.

Real Windows Security Event Logs and local authentication data are excluded from version control through `.gitignore`.

---

## Project Goals

Sentinel was developed to explore practical cybersecurity concepts and demonstrate how software engineering can be applied to security monitoring.

The project focuses on:

- Authentication monitoring.
- Security event analysis.
- Brute-force attack detection.
- IP-based threat identification.
- Backend authentication and account management.
- Real-time monitoring interfaces.
- Windows security event collection.
- Automated testing and validation.

---

## Author

**Caleb Hoke**

GitHub: [@CjHoke](https://github.com/CjHoke)

Portfolio: [Personal Portfolio](https://cjhoke.github.io/personal-portfolio/)

