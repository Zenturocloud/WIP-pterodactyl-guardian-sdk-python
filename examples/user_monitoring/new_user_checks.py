#!/usr/bin/env python3
from pterodactyl_guardian import PterodactylGuardian
from datetime import datetime
import json
import os

# Initialize the Guardian
guardian = PterodactylGuardian(
    panel_url="https://panel.yourdomain.com",
    api_key="your-pterodactyl-api-key",
    api_type="application"
)

# Configuration
ALERT_WEBHOOK = "https://discord.com/api/webhooks/your-webhook-url"
LOG_DIRECTORY = "security_logs"
SUSPICIOUS_SCORE_THRESHOLD = 0.7

# Ensure log directory exists
os.makedirs(LOG_DIRECTORY, exist_ok=True)

def log_suspicious_activity(user_data, detection_result):
    """Log suspicious activity to file and send alerts"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_id = user_data.get("id", "unknown")
    username = user_data.get("username", f"User {user_id}")
    email = user_data.get("email", "unknown")
    
    # Create detailed log entry
    log_entry = {
        "timestamp": timestamp,
        "user_id": user_id,
        "username": username,
        "email": email,
        "suspicion_score": detection_result["suspicion_score"],
        "detection_modules": [
            {
                "module": module,
                "score": details["score"],
                "is_suspicious": details["is_suspicious"],
                "matches": details.get("matches", [])
            }
            for module, details in detection_result["module_results"].items()
        ]
    }
    
    # Save to log file
    log_file = os.path.join(LOG_DIRECTORY, f"suspicious_activity_{user_id}.json")
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    # Add note to user's account
    guardian.add_user_note(
        user_id=user_id,
        note=f"[SECURITY] Suspicious activity detected at {timestamp}. Score: {detection_result['suspicion_score']:.2f}"
    )
    
    # Send alert notification
    if ALERT_WEBHOOK and detection_result["suspicion_score"] > SUSPICIOUS_SCORE_THRESHOLD:
        guardian.notify_admin(
            subject=f"High-Risk User Activity: {username}",
            message=f"User {username} (ID: {user_id}, Email: {email}) has triggered high-risk security detection.\n\n"
                   f"Suspicion Score: {detection_result['suspicion_score']:.2f}\n"
                   f"Detection Time: {timestamp}\n\n"
                   f"This user may be attempting to abuse the platform. Please review their account."
        )
    
    return log_entry

def scan_all_users():
    """Scan all users for suspicious activity"""
    print("Starting complete user scan...")
    users = guardian.get_users()
    suspicious_count = 0
    
    for user in users:
        user_id = user.get("attributes", {}).get("id")
        if not user_id:
            continue
            
        # Check user activity
        detection_result = guardian.check_user_activity(user_id=user_id)
        
        if detection_result["is_suspicious"]:
            suspicious_count += 1
            log_entry = log_suspicious_activity(user.get("attributes", {}), detection_result)
            print(f"⚠️  Suspicious user detected: {log_entry['username']} (Score: {log_entry['suspicion_score']:.2f})")
    
    print(f"Scan complete. Found {suspicious_count} suspicious users out of {len(users)} total users.")

def monitor_new_users():
    """Set up continuous monitoring for new users"""
    def new_user_handler(results):
        for user in results.get("new_users", []):
            print(f"🔔 New user detected: {user['username']} (ID: {user['id']})")
            
            # Check if user is suspicious
            if user.get("suspicion_score", 0) > SUSPICIOUS_SCORE_THRESHOLD:
                print(f"⚠️  New user has suspicious indicators: {user['username']}")
                
                # Get full user details
                user_details = guardian.get_user_details(user["id"])
                
                # Run full check
                detection_result = guardian.check_user_activity(user_id=user["id"])
                if detection_result["is_suspicious"]:
                    log_suspicious_activity(user_details, detection_result)
    
    # Start monitoring for new users
    user_monitor = guardian.monitor_new_users(
        interval_hours=1,
        callback=new_user_handler
    )
    
    return user_monitor

def setup_event_monitoring():
    """Set up event-based monitoring for real-time detection"""
    event_processor = guardian.start_event_processing()
    
    @event_processor.on("user.create")
    def on_user_created(event_data):
        user_id = event_data["attributes"]["id"]
        print(f"🔔 Real-time event: New user created: {event_data['attributes']['username']}")
        
        # Run immediate check on new user
        detection_result = guardian.check_user_activity(user_id=user_id)
        if detection_result["is_suspicious"]:
            log_suspicious_activity(event_data["attributes"], detection_result)
    
    @event_processor.on("user.update")
    def on_user_updated(event_data):
        # Only check specific updates that might indicate account takeover
        if "email" in event_data.get("attributes", {}).get("changed", {}):
            user_id = event_data["attributes"]["id"]
            print(f"🔍 Real-time event: User email changed: {event_data['attributes']['username']}")
            
            # Run focused check
            detection_result = guardian.check_user_activity(
                user_id=user_id,
                activity_data={"type": "email_change", "details": event_data["attributes"]["changed"]}
            )
            
            if detection_result["is_suspicious"]:
                log_suspicious_activity(event_data["attributes"], detection_result)
    
    return event_processor

if __name__ == "__main__":
    # Run an initial scan of all users
    scan_all_users()
    
    # Set up continuous monitoring
    user_monitor = monitor_new_users()
    event_processor = setup_event_monitoring()
    
    print("\n✅ User monitoring active. Press Ctrl+C to stop.")
    
    try:
        # Keep the script running
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping user monitoring...")
        guardian.stop_all_checks()
        print("Monitoring stopped.")
