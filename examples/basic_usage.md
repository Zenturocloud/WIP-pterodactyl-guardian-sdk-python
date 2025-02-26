# Basic Usage of Pterodactyl Guardian SDK

This example demonstrates how to set up Pterodactyl Guardian and start monitoring your Pterodactyl Panel installation.

## Installation

```bash
pip install pterodactyl-guardian
```

## Basic Setup

```python
from pterodactyl_guardian import PterodactylGuardian

# Initialize with your Pterodactyl Panel details
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"  # Use 'application' for admin API, 'client' for user API
)

# Test the connection
if guardian.test_connection():
    print("✅ Successfully connected to Pterodactyl Panel")
else:
    print("❌ Failed to connect to Pterodactyl Panel")
```

## Quick Start with Default Configuration

For a fully automated setup with sensible defaults:

```python
import time
from pterodactyl_guardian import PterodactylGuardian

# Initialize Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key"
)

# Start all monitoring systems with default settings
# This will:
# - Monitor for new users every hour
# - Scan server files daily
# - Check resource usage every 15 minutes
# - Process Pterodactyl events in real-time

user_monitor = guardian.monitor_new_users()
file_monitor = guardian.monitor_server_files()
resource_monitor = guardian.monitor_resource_usage()
event_processor = guardian.start_event_processing()

print("Guardian is now protecting your Pterodactyl installation.")
print("Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    guardian.stop_all_checks()
    print("Guardian stopped.")
```

## Advanced Configuration

For more control over how Guardian operates:

```python
from pterodactyl_guardian import PterodactylGuardian, DetectionModules, AnalysisLevel

guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    
    # Only enable specific detection modules
    enabled_modules=[
        DetectionModules.OBFUSCATION,
        DetectionModules.WEB_SERVER,
        DetectionModules.SECURITY
    ],
    
    # Configure analysis depth
    analysis_level=AnalysisLevel.DEEP,
    
    # Custom detection thresholds
    detection_thresholds={
        DetectionModules.OBFUSCATION: 0.5,  # More sensitive
        DetectionModules.WEB_SERVER: 0.8,   # Less sensitive
    },
    
    # Configure learning mode
    learning_mode="aggressive",
    
    # Resource limits
    max_cpu_percent=20,
    max_memory_mb=200,
    scan_threads=2,
    
    # Alert configuration
    alert_webhook="https://your-webhook-url.com/alerts"
)
```

## Checking Current Status

```python
# Get all servers
servers = guardian.get_servers()
print(f"Found {len(servers)} servers")

# Get all users
users = guardian.get_users()
print(f"Found {len(users)} users")

# Get details about a specific server
server = guardian.get_server_details(server_id="123")
print(f"Server name: {server['name']}")

# Check resource usage for a server
resources = guardian.get_server_resources(server_id="123")
print(f"CPU usage: {resources['cpu']}%")
print(f"Memory usage: {resources['memory']} MB")
```

In the next examples, we'll explore how to handle monitoring events, scan files, and create custom detection rules.
