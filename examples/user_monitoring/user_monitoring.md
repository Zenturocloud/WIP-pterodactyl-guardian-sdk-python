# User Monitoring with Pterodactyl Guardian

This directory contains examples for monitoring user activities and detecting suspicious behaviors using the Pterodactyl Guardian SDK.

## 📋 Overview

The examples demonstrate how to:

- Monitor for new user registrations
- Detect suspicious user activities
- Set up automated responses to security incidents
- Create custom detection rules for user behavior

## 🔧 Prerequisites

- A Pterodactyl Panel installation
- Administrative API key with appropriate permissions
- Python 3.7 or higher
- Pterodactyl Guardian SDK installed

## 📁 Examples

### 1. New User Detection

The `new_user_checks.py` script demonstrates how to set up continuous monitoring for new user registrations and analyze them for suspicious patterns automatically.

```python
from pterodactyl_guardian import PterodactylGuardian

# Initialize Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"
)

# Define handler for new users
def process_new_users(results):
    for user in results.get("new_users", []):
        print(f"New user detected: {user['username']} (Email: {user['email']})")
        
        if user.get("suspicion_score", 0) > 0.7:
            print(f"⚠️ Suspicious user! Score: {user['suspicion_score']}")
            print(f"Reasons: {', '.join(user.get('suspicion_reasons', []))}")

# Start monitoring
monitor = guardian.monitor_new_users(
    interval_hours=1,
    callback=process_new_users
)
```

### 2. User Activity Analysis

The `suspicious_activity.py` script shows how to detect suspicious user activities in real-time by monitoring user events and analyzing them against behavioral baselines.

```python
from pterodactyl_guardian import PterodactylGuardian
from pterodactyl_guardian.enums import DetectionModules

# Initialize Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key"
)

# Start event monitoring
event_processor = guardian.start_event_processing()

@event_processor.on("user.update")
def handle_user_update(event_data):
    user_id = event_data["attributes"]["id"]
    
    # Check for suspicious activity
    result = guardian.check_user_activity(
        user_id=user_id,
        activity_data=event_data["attributes"],
        detection_modules=[
            DetectionModules.AUTOMATION,
            DetectionModules.SPAM,
            DetectionModules.DATA_HARVESTING
        ]
    )
    
    if result["is_suspicious"]:
        print(f"⚠️ Suspicious activity detected for user {user_id}")
        print(f"Score: {result['suspicion_score']}")
```

### 3. Behavioral Baselining

The `user_baselining.py` script demonstrates how to establish normal behavior patterns for users and detect deviations that could indicate compromise or abuse.

```python
from pterodactyl_guardian import PterodactylGuardian
from pterodactyl_guardian.intelligence import BehavioralBaselining

# Initialize Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key"
)

# Get all users
users = guardian.get_users()

# Process user activity to establish baselines
for user in users:
    user_id = user["attributes"]["id"]
    
    # Collect historical activity
    activity_data = {
        "user_id": user_id,
        "timestamp": user["attributes"]["created_at"],
        "ip_address": user["attributes"].get("ip", "unknown"),
        "type": "account_creation"
    }
    
    # Update behavioral baseline
    guardian.intelligence.baselining.update_user_activity_baseline(
        user_id=user_id,
        data=activity_data
    )
```

## 🚀 Running the Examples

1. Install the Pterodactyl Guardian SDK:
   ```
   pip install pterodactyl-guardian
   ```

2. Copy the example scripts and modify the panel URL and API key:
   ```python
   guardian = PterodactylGuardian(
       panel_url="https://your-actual-panel.com",
       api_key="your-actual-api-key"
   )
   ```

3. Run the desired example:
   ```
   python new_user_checks.py
   ```

## 🔍 Expected Output

When running the `new_user_checks.py` example, you'll see output similar to this:

```
Starting new user monitoring...
Checking for new users...
New user detected: testuser (Email: test@example.com)
New user detected: admin2 (Email: admin@example.com)
⚠️ Suspicious user! Score: 0.8
Reasons: Suspicious username pattern, Unusual registration time
```

## 📝 Advanced Configuration

You can customize the detection sensitivity by adjusting thresholds:

```python
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    detection_thresholds={
        "automation": 0.7,
        "spam": 0.6,
        "data_harvesting": 0.8
    }
)
```

## 🔒 Security Best Practices

- Never hardcode API keys in production code
- Set up proper alerting for high-severity detections
- Regularly review detection logs to fine-tune thresholds
- Combine multiple detection modules for better accuracy
