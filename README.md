
# Java Security Log Analyzer

A command-line security log analysis application built with Java 25 and Maven. The application parses structured security logs, identifies suspicious login activity, detects potential brute-force and password-spraying behavior, and generates timestamped security reports.

## Features

- **Log Parsing:** Reads structured security log files and extracts timestamps, IP addresses, event types, usernames, and descriptions.
- **Malformed Log Detection:** Identifies invalid log entries while continuing to process valid entries.
- **Failed Login Analysis:** Counts failed login attempts by source IP address.
- **Suspicious IP Detection:** Flags IP addresses that exceed a configurable failed-login threshold.
- **Brute-Force Detection:** Identifies repeated failed login attempts within a configurable time window.
- **Successful Login Correlation:** Detects successful logins following repeated failed attempts.
- **Password-Spraying Detection:** Identifies source IP addresses attempting authentication against multiple usernames within a time window.
- **Automated Reporting:** Generates timestamped text reports containing analysis findings and parsing results.
- **Command-Line Interface:** Supports configurable detection thresholds and built-in usage instructions.

## Technologies

- Java 25
- Maven
- JUnit 5
- IntelliJ IDEA

## Project Structure

```text
Java-Security-Log-Analyzer/
├── logs/
│   ├── sample-security.log
│   └── password-spraying-test.log
├── reports/
├── src/
│   ├── main/java/com/calebhoke/securityanalyzer/
│   │   ├── analyzer/
│   │   ├── model/
│   │   ├── parser/
│   │   ├── report/
│   │   └── Main.java
│   └── test/java/com/calebhoke/securityanalyzer/
│       ├── analyzer/
│       ├── parser/
│       └── report/
├── pom.xml
└── README.md
```

## Requirements

- Java 25 or later
- Maven

## Building the Application

Clone the repository and navigate to the project directory.

Build the application using Maven:

```bash
mvn clean package
```

The executable JAR will be generated at:

```text
target/security-log-analyzer.jar
```

## Running the Application

Display usage instructions:

```bash
java -jar target/security-log-analyzer.jar --help
```

Run the analyzer with the sample log:

```bash
java -jar target/security-log-analyzer.jar logs/sample-security.log
```

Run with custom detection thresholds:

```bash
java -jar target/security-log-analyzer.jar logs/sample-security.log 3 5 3
```

### Command-Line Arguments

| Argument | Description | Default |
|---|---|---|
| log-file | Path to the security log file | logs/sample-security.log |
| failed-login-threshold | Minimum failures to flag a suspicious IP | 3 |
| detection-window-minutes | Time window used for attack detection | 5 |
| brute-force-threshold | Minimum failures for brute-force detection | 3 |

Password-spraying detection currently uses a minimum of 3 unique usernames.

## Log File Format

The analyzer expects pipe-delimited log entries:

```text
timestamp|ip-address|event-type|username|description
```

Example:

```text
2026-11-13T10:00:00|192.168.1.100|FAILED_LOGIN|admin|Invalid password
2026-11-13T10:01:00|192.168.1.100|FAILED_LOGIN|admin|Invalid password
2026-11-13T10:02:00|192.168.1.100|SUCCESSFUL_LOGIN|admin|Login successful
```

## Reports

After analysis, the application generates a timestamped report in the `reports/` directory.

Reports include:

- Parsing results and malformed entries
- Failed login summaries
- Suspicious IP addresses
- Brute-force detection findings
- Successful logins following repeated failures
- Potential password-spraying activity

## Testing

The project includes JUnit 5 unit tests covering:

- Log parsing
- Malformed log handling
- Security analysis
- Detection thresholds and time windows
- Report generation

Run the test suite with:

```bash
mvn test
```

## Detection Limitations

This application identifies patterns that may indicate suspicious authentication activity. Its findings are indicators for further investigation, not definitive proof of an attack.

Password-spraying detection is based on failed authentication attempts against multiple unique usernames from a single IP address within a configured time window. The current log format does not record attempted passwords, so the analyzer cannot verify whether the same password was used across accounts.

## Author

Caleb Hoke
