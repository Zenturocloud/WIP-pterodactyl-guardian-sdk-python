# Pterodactyl Guardian SDK for Python

A comprehensive Python SDK for implementing abuse detection and security monitoring for Pterodactyl Panel via the Pterodactyl API.

[![PyPI version](https://img.shields.io/pypi/v/pterodactyl-guardian.svg)](https://pypi.org/project/pterodactyl-guardian/)
[![Python versions](https://img.shields.io/pypi/pyversions/pterodactyl-guardian.svg)](https://pypi.org/project/pterodactyl-guardian/)
[![License](https://img.shields.io/pypi/l/pterodactyl-guardian.svg)](https://github.com/yourusername/pterodactyl-guardian-sdk-python/blob/main/LICENSE)

## Overview

Pterodactyl Guardian provides server administrators with a powerful toolkit for monitoring and protecting Pterodactyl Panel installations against abuse. The SDK uses the Pterodactyl API to check for suspicious activities, scan files, monitor resource usage, and detect potential security threats.

## Key Features

- **API-Based Monitoring**: Leverages the Pterodactyl API for all monitoring and security operations
- **Scheduled Checks**: Automatically scan for new users, suspicious activities, or file changes at regular intervals
- **Event Detection**: Process Pterodactyl events to identify suspicious patterns
- **File Security**: Scan server files and uploads for malicious content or obfuscated code
- **User Monitoring**: Detect suspicious user behavior and potential account abuse
- **Resource Monitoring**: Identify resource abuse across servers and instances
- **Comprehensive Detection**: Specialized modules for various abuse types (bots, spam, data harvesting, etc.)

## Installation

```bash
pip install pterodactyl-guardian
```

## Quick Start Examples

### Basic Setup

```python
from pterodactyl_guardian import PterodactylGuardian

# Initialize the SDK with your Pterodactyl Panel API details
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"  # Use 'application' for admin API, 'client' for user API
)

# Test connection
is_connected = guardian.test_connection()
print(f"Connected to Pterodactyl Panel: {is_connected}")
```

### Scheduled User Monitoring

```python
from pterodactyl_guardian import PterodactylGuardian
from pterodactyl_guardian.scheduler import ScheduledCheck

# Initialize the Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"
)

# Create a scheduled check for new users (runs every hour)
user_monitor = ScheduledCheck(
    interval_hours=1,
    check_type="new_users",
    callback=lambda results: process_new_users(results),
    detection_modules=["automation", "spam"]
)

def process_new_users(results):
    for user in results.new_users:
        if user.suspicion_score > 0.7:
            print(f"Suspicious new user detected: {user.username} (Score: {user.suspicion_score})")
            # Take action (log, notify admin, add restrictions, etc.)
            guardian.add_user_note(user.id, "Flagged as potentially suspicious by Guardian")

# Start monitoring
user_monitor.start()
```

### Server File Scanning

```python
from pterodactyl_guardian import PterodactylGuardian
from pterodactyl_guardian.scheduler import ScheduledCheck

# Initialize the Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"
)

# Get all servers
servers = guardian.get_servers()

# Scan files on all servers (scheduled daily)
file_scanner = ScheduledCheck(
    interval_hours=24,
    check_type="server_files",
    target_servers=servers,  # Can also specify server IDs: [1, 2, 3]
    file_patterns=["*.php", "*.js", "*.py"],  # Patterns to scan
    detection_modules=["obfuscation", "web_server", "security"],
    callback=lambda results: handle_suspicious_files(results)
)

def handle_suspicious_files(results):
    for server_id, files in results.suspicious_files.items():
        if files:
            server_name = guardian.get_server_name(server_id)
            print(f"Suspicious files detected on server {server_name}:")
            for file in files:
                print(f"  - {file.path} (Threat: {file.threat_type}, Score: {file.threat_score})")
                # Take action (backup, quarantine, notify admin, etc.)

# Start file scanning
file_scanner.start()
```

### Resource Usage Monitoring

```python
from pterodactyl_guardian import PterodactylGuardian
from pterodactyl_guardian.scheduler import ScheduledCheck

# Initialize the Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"
)

# Monitor resource usage (runs every 15 minutes)
resource_monitor = ScheduledCheck(
    interval_minutes=15,
    check_type="resource_usage",
    resource_types=["cpu", "memory", "disk", "network"],
    thresholds={
        "cpu": 90,  # Alert if CPU usage exceeds 90%
        "memory": 85,  # Alert if memory usage exceeds 85%
        "disk": 95,  # Alert if disk usage exceeds 95%
        "network": 10000000  # Alert if network traffic exceeds 10MB/s
    },
    callback=lambda results: handle_resource_alerts(results)
)

def handle_resource_alerts(results):
    for server_id, alerts in results.resource_alerts.items():
        if alerts:
            server_name = guardian.get_server_name(server_id)
            print(f"Resource alerts for server {server_name}:")
            for alert in alerts:
                print(f"  - {alert.resource_type}: {alert.current_value}% (Threshold: {alert.threshold}%)")
                
                # Investigate suspicious processes
                if alert.suspicious_processes:
                    print("  - Suspicious processes detected:")
                    for proc in alert.suspicious_processes:
                        print(f"    * {proc.name} (PID: {proc.pid})")
                
                # Take action (notify admin, suspend server, etc.)

# Start resource monitoring
resource_monitor.start()
```

### Processing Pterodactyl Events

```python
from pterodactyl_guardian import PterodactylGuardian
from pterodactyl_guardian.events import EventProcessor

# Initialize the Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"
)

# Create event processor
event_processor = EventProcessor(guardian)

# Process server creation events
@event_processor.on("server.create")
def server_created(event_data):
    # Check for suspicious server creation patterns
    server_id = event_data["attributes"]["id"]
    owner_id = event_data["attributes"]["user"]
    
    # Count servers owned by this user
    user_servers = guardian.get_user_servers(owner_id)
    
    if len(user_servers) > 10:
        print(f"User {owner_id} has created many servers ({len(user_servers)})")
        guardian.log_suspicious_activity(
            user_id=owner_id,
            activity_type="excessive_server_creation",
            details=f"User has created {len(user_servers)} servers"
        )

# Process user update events
@event_processor.on("user.update")
def user_updated(event_data):
    # Check for suspicious account changes
    user_id = event_data["attributes"]["id"]
    changes = event_data["attributes"]["changed"]
    
    if "email" in changes:
        # Email change detected, check for suspicious patterns
        new_email = changes["email"]["new"]
        old_email = changes["email"]["old"]
        
        if guardian.is_suspicious_email(new_email):
            print(f"Suspicious email change detected for user {user_id}")
            guardian.log_suspicious_activity(
                user_id=user_id,
                activity_type="suspicious_email_change",
                details=f"Changed email from {old_email} to {new_email}"
            )

# Start event processing
event_processor.start()
```

### Checking New Server Files

```python
from pterodactyl_guardian import PterodactylGuardian
from pterodactyl_guardian.scheduler import ScheduledCheck

# Initialize the Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"
)

# Scan for new files only (runs every 3 hours)
new_file_scanner = ScheduledCheck(
    interval_hours=3,
    check_type="new_files",
    target_servers="all",  # Scan all servers
    file_patterns=["*.php", "*.js", "*.py"],
    detection_modules=["obfuscation", "web_server", "security"],
    callback=lambda results: handle_new_files(results)
)

def handle_new_files(results):
    for server_id, new_files in results.new_files.items():
        if new_files:
            server_name = guardian.get_server_name(server_id)
            print(f"New files detected on server {server_name}:")
            
            # Scan each new file
            for file_path in new_files:
                scan_result = guardian.scan_file(server_id, file_path)
                
                if scan_result.is_suspicious:
                    print(f"  - Suspicious file: {file_path}")
                    print(f"    Threat: {scan_result.threat_type}")
                    print(f"    Score: {scan_result.threat_score}")
                    
                    # Take action
                    if scan_result.threat_score > 0.8:
                        guardian.quarantine_file(server_id, file_path)
                        guardian.notify_admin(
                            subject="High-risk file detected",
                            message=f"Quarantined suspicious file on server {server_name}: {file_path}"
                        )

# Start new file scanning
new_file_scanner.start()
```

## Configuration Options

```python
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application",  # 'application' or 'client'
    log_level="INFO",
    scan_threads=4,  # Number of threads for parallel scanning
    cache_results=True,  # Cache API results
    cache_ttl=3600,  # Cache time-to-live in seconds
    alert_webhook="https://your-webhook-url.com/alerts",
    api_timeout=30,  # API request timeout in seconds
    adaptive_learning=True  # Adjust thresholds based on historical data
)
```

## Available Detection Modules

- `automation` - Bot & automation detection
- `network` - Network abuse protection
- `resource` - Resource abuse prevention
- `spam` - Spam & mass communication filtering
- `data_harvesting` - Data harvesting protection
- `game_server` - Game server exploit detection
- `web_server` - Web server vulnerability detection
- `infrastructure` - Infrastructure protection
- `security` - General security threat detection
- `obfuscation` - Code obfuscation analysis

## Examples

Check the `examples/` directory for more integration patterns:

- Scheduled API monitoring
- New user verification
- Server resource monitoring
- Game server protection
- File change detection
- Abuse pattern detection
- Custom event handling

## Documentation

For detailed API documentation, please visit our [official documentation site](https://docs.pterodactyl-guardian.com).

## Project Status

This is a closed-source project maintained by ZenturoCloud. While we welcome feedback, bug reports, and feature requests through the Issues section, we are not accepting code contributions at this time.

The SDK is professionally maintained and regularly updated to ensure compatibility with the latest API versions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please contact support@zenturocloud.com or open an issue on our GitHub repository.
