# Pterodactyl Guardian SDK

An intelligent and adaptive security monitoring system for Pterodactyl Panel that automatically detects, analyzes, and protects against abuse.

[![PyPI version](https://img.shields.io/pypi/v/pterodactyl-guardian.svg)](https://pypi.org/project/pterodactyl-guardian/)
[![Python versions](https://img.shields.io/pypi/pyversions/pterodactyl-guardian.svg)](https://pypi.org/project/pterodactyl-guardian/)
[![License](https://img.shields.io/pypi/l/pterodactyl-guardian.svg)](https://github.com/Zenturocloud/pterodactyl-guardian-sdk-python/blob/main/LICENSE)

## Overview

Pterodactyl Guardian is an advanced security solution that leverages AI-driven analysis to protect your Pterodactyl Panel installation from security threats, abuse, and malicious activities. The system continuously learns from your environment and admin feedback to provide increasingly accurate protection tailored to your specific deployment.

Unlike traditional security tools that rely on static rules, Pterodactyl Guardian employs intelligent pattern recognition, code analysis, and behavioral prediction to identify threats even as they evolve and adapt.

## Key Features

### 🧠 Intelligent Analysis
- **Adaptive Learning System**: Learns from admin feedback to reduce false positives
- **Contextual Awareness**: Understands your environment and adapts accordingly
- **Advanced Code Analysis**: Goes beyond pattern matching with structural understanding
- **Behavioral Prediction**: Simulates what suspicious code would do if executed
- **Signal Correlation**: Connects multiple indicators to identify sophisticated threats

### 🔍 Comprehensive Detection
- **Bot & Automation Detection**: Identifies automation tools across major platforms
- **Network Abuse Protection**: Detects port scanning, DDoS attempts, and more
- **Resource Abuse Prevention**: Guards against crypto miners and resource exhaustion
- **Spam & Mass Communication Filtering**: Blocks mass messaging and spam attempts
- **Data Harvesting Protection**: Prevents unauthorized scraping and data collection
- **Game Server Protection**: Specific protection for game server environments
- **Web Server Protection**: Detects SQL injection, XSS, and web vulnerabilities
- **Infrastructure Protection**: Guards against container escapes and privilege escalation
- **Obfuscation Analysis**: Uncovers hidden malicious code using 20+ detection methods

### ⚙️ Flexible Configuration
- **Plug and Play**: Works with minimal setup (URL + API key)
- **Modular Design**: Enable/disable specific detection modules as needed
- **Configurable Thresholds**: Fine-tune sensitivity per module
- **Resource Controls**: Adjust CPU/memory usage to suit your environment
- **Storage Options**: Local SQLite or external database for larger deployments

### 📊 Comprehensive Monitoring
- **User Activity Monitoring**: Tracks suspicious user behavior
- **File System Monitoring**: Detects malicious file uploads and modifications
- **Resource Usage Monitoring**: Identifies abnormal resource consumption
- **Event-Based Analysis**: Responds to Pterodactyl Panel events in real-time
- **Scheduled Scanning**: Regular security audits with configurable frequency

## Installation

```bash
pip install pterodactyl-guardian
```

## Quick Start

### Basic Setup (Just Works™)

```python
from pterodactyl_guardian import PterodactylGuardian

# Initialize with minimal configuration
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key"
)

# Start monitoring with intelligent defaults
guardian.start_monitoring()

# Wait for events
for event in guardian.events():
    if event.is_threat:
        print(f"Detected {event.threat_type} on server {event.server_name}")
        event.take_action()  # Auto-remediate based on threat type
```

### Advanced Configuration

```python
from pterodactyl_guardian import PterodactylGuardian, DetectionModules, AnalysisLevel

guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    
    # Enable specific modules
    enabled_modules=[
        DetectionModules.OBFUSCATION,
        DetectionModules.NETWORK,
        DetectionModules.WEB_SERVER
    ],
    
    # Configure intelligence
    analysis_level=AnalysisLevel.DEEP,  # Deepest code analysis
    learning_mode="aggressive",         # Learn quickly from feedback
    
    # System resources
    max_cpu_percent=20,                 # Cap CPU usage
    max_memory_mb=300,                  # Limit memory usage
    scan_threads=4,                     # Parallel scanning threads
    
    # Configure storage
    storage_engine="sqlite",            # Or "postgresql"
    data_retention_days=90,             # History retention
    
    # Runtime behavior
    check_interval_minutes=30,          # Scheduled check frequency
    alert_webhook="https://your-webhook.com/alerts"
)

# Register custom feedback handler
@guardian.on_detection
def handle_detection(threat):
    if admin_review(threat.details):
        threat.approve()   # False positive - system learns
    else:
        threat.quarantine() # Confirmed threat - system reinforces
```

## Core Components

### Smart Detection Engine
The heart of Pterodactyl Guardian is its intelligent detection engine that combines multiple analysis techniques:

1. **Pattern Analysis**: Baseline detection using optimized pattern matching
2. **Structural Analysis**: Understanding code structure through AST parsing
3. **Behavioral Analysis**: Predicting what code will do when executed
4. **Contextual Analysis**: Evaluating findings in the context of your environment

### Adaptive Learning System
Pterodactyl Guardian continuously improves through:

- **Feedback Processing**: Learning from admin decisions
- **Behavioral Baselining**: Establishing normal patterns
- **Pattern Evolution**: Tracking how threats change over time
- **Confidence Calibration**: Adjusting thresholds based on accuracy

### Monitoring Systems
Multiple monitoring approaches ensure comprehensive coverage:

- **Scheduled Checks**: Regular security auditing
- **Event Monitoring**: Real-time response to panel events
- **File System Monitoring**: Detecting new or changed files
- **Resource Monitoring**: Identifying abnormal resource usage

## Configuration Options

Pterodactyl Guardian provides extensive configuration options. Here are the most important ones:

| Option | Description | Default |
|--------|-------------|---------|
| `panel_url` | URL to your Pterodactyl Panel | Required |
| `api_key` | Your Pterodactyl API key | Required |
| `api_type` | API key type (application or client) | "application" |
| `enabled_modules` | List of detection modules to enable | All modules |
| `analysis_level` | Depth of analysis (basic, standard, deep) | "standard" |
| `learning_mode` | Learning approach (conservative, balanced, aggressive) | "balanced" |
| `max_cpu_percent` | Maximum CPU usage | 30% |
| `max_memory_mb` | Maximum memory usage in MB | 250 |
| `scan_threads` | Number of parallel scanning threads | 2 |
| `storage_engine` | Storage backend (sqlite, postgresql) | "sqlite" |
| `check_interval_minutes` | Minutes between scheduled checks | 60 |
| `alert_webhook` | Webhook URL for alerts | None |
| `detection_thresholds` | Custom thresholds for detection modules | Module defaults |
| `quarantine_action` | Action to take on quarantine | "rename" |
| `data_retention_days` | Days to keep historical data | 30 |

## Available Detection Modules

Pterodactyl Guardian includes the following detection modules:

- `AUTOMATION`: Bot & automation detection
- `NETWORK`: Network abuse protection
- `RESOURCE`: Resource abuse prevention
- `SPAM`: Spam & mass communication filtering
- `DATA_HARVESTING`: Data harvesting protection
- `GAME_SERVER`: Game server exploit detection
- `WEB_SERVER`: Web server vulnerability detection
- `INFRASTRUCTURE`: Infrastructure protection
- `SECURITY`: General security threat detection
- `OBFUSCATION`: Code obfuscation analysis

## Performance Considerations

Pterodactyl Guardian is designed to be efficient and respectful of system resources:

- **Base Memory Usage**: 50-150MB depending on configuration
- **Peak CPU Usage**: 5-25% during active scanning (configurable)
- **Idle Resource Usage**: <1% CPU, minimal memory
- **Storage Requirements**: 100MB-2GB depending on history retention

The system includes automatic throttling and resource management to prevent impact on server performance.

## Development

## Project Status

This is a closed-source project maintained by ZenturoCloud. While we welcome feedback, bug reports, and feature requests through the Issues section, we are not accepting code contributions at this time.

The SDK is professionally maintained and regularly updated to ensure compatibility with the latest API versions.

### Testing
Run the test suite with:
```bash
pytest
```

### License
This project is licensed under the MIT License - see the LICENSE file for details.

## Support
For issues, questions please open an issue on GitHub.
