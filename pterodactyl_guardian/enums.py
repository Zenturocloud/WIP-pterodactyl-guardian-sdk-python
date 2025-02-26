"""
Enumerations for the Pterodactyl Guardian SDK.

This module provides enumeration classes for various options and settings
used throughout the SDK, providing type safety and intellisense benefits.
"""

from enum import Enum, auto


class DetectionModules(str, Enum):
    """Available detection modules in the Guardian SDK."""
    
    AUTOMATION = "automation"
    NETWORK = "network"
    RESOURCE = "resource"
    SPAM = "spam"
    DATA_HARVESTING = "data_harvesting"
    GAME_SERVER = "game_server"
    WEB_SERVER = "web_server"
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    OBFUSCATION = "obfuscation"
    
    @classmethod
    def all(cls):
        """Get a list of all available modules."""
        return [module.value for module in cls]


class AnalysisLevel(str, Enum):
    """Code analysis depth levels."""
    
    BASIC = "basic"  # Fast pattern matching only
    STANDARD = "standard"  # Pattern matching + basic structure analysis
    DEEP = "deep"  # Full code analysis, behavioral prediction, etc.


class LearningMode(str, Enum):
    """Learning approach for the adaptive system."""
    
    CONSERVATIVE = "conservative"  # Slow to learn, prioritizes avoiding false negatives
    BALANCED = "balanced"  # Balanced approach to learning
    AGGRESSIVE = "aggressive"  # Quick to learn, may have more false positives initially


class StorageEngine(str, Enum):
    """Available storage backends."""
    
    SQLITE = "sqlite"  # Local SQLite database
    POSTGRESQL = "postgresql"  # PostgreSQL database
    MEMORY = "memory"  # In-memory storage (non-persistent)


class ScheduleFrequency(str, Enum):
    """Predefined scheduling frequencies."""
    
    HOURLY = "hourly"  # Run once per hour
    DAILY = "daily"  # Run once per day
    WEEKLY = "weekly"  # Run once per week
    REALTIME = "realtime"  # Run continuously


class QuarantineAction(str, Enum):
    """Actions to take when quarantining a file."""
    
    RENAME = "rename"  # Rename the file with .quarantined extension
    MOVE = "move"  # Move to quarantine directory
    BACKUP_REMOVE = "backup_remove"  # Backup and then remove
    REMOVE = "remove"  # Remove the file (use with caution)


class ThreatSeverity(str, Enum):
    """Severity levels for detected threats."""
    
    LOW = "low"  # Low severity threat
    MEDIUM = "medium"  # Medium severity threat
    HIGH = "high"  # High severity threat
    CRITICAL = "critical"  # Critical severity threat


class APIType(str, Enum):
    """Types of Pterodactyl API keys."""
    
    APPLICATION = "application"  # Admin API key
    CLIENT = "client"  # User/client API key
