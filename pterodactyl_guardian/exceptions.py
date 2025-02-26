"""
Custom exceptions for the Pterodactyl Guardian SDK.

This module defines all exceptions raised by the SDK to provide
clear error handling and appropriate exception hierarchies.
"""


class PterodactylGuardianError(Exception):
    """Base exception for all Pterodactyl Guardian errors."""
    pass


class ConfigurationError(PterodactylGuardianError):
    """Exception raised for errors in the configuration."""
    pass


class APIError(PterodactylGuardianError):
    """Exception raised for errors in the API communication."""
    
    def __init__(self, message, status_code=None, response=None, endpoint=None):
        self.status_code = status_code
        self.response = response
        self.endpoint = endpoint
        super().__init__(message)


class AuthenticationError(APIError):
    """Exception raised when authentication with the Pterodactyl API fails."""
    pass


class ResourceNotFoundError(APIError):
    """Exception raised when a requested resource is not found."""
    pass


class RateLimitError(APIError):
    """Exception raised when the API rate limit is exceeded."""
    pass


class ConnectionError(APIError):
    """Exception raised when there is an error connecting to the API."""
    pass


class StorageError(PterodactylGuardianError):
    """Exception raised when there is an error with data storage."""
    pass


class DatabaseError(StorageError):
    """Exception raised when there is a database error."""
    pass


class MigrationError(DatabaseError):
    """Exception raised when there is an error with database migrations."""
    pass


class DetectionError(PterodactylGuardianError):
    """Exception raised when there is an error in the detection system."""
    pass


class AnalysisError(PterodactylGuardianError):
    """Exception raised when there is an error in code analysis."""
    pass


class ParserError(AnalysisError):
    """Exception raised when there is an error parsing code."""
    pass


class MonitoringError(PterodactylGuardianError):
    """Exception raised when there is an error in the monitoring system."""
    pass


class SchedulerError(MonitoringError):
    """Exception raised when there is an error in the scheduler."""
    pass


class EventError(MonitoringError):
    """Exception raised when there is an error processing events."""
    pass


class ResourceMonitorError(MonitoringError):
    """Exception raised when there is an error monitoring resources."""
    pass


class FileMonitorError(MonitoringError):
    """Exception raised when there is an error monitoring files."""
    pass


class IntelligenceError(PterodactylGuardianError):
    """Exception raised when there is an error in the intelligence system."""
    pass


class LearningError(IntelligenceError):
    """Exception raised when there is an error in the learning system."""
    pass


class PredictionError(IntelligenceError):
    """Exception raised when there is an error making behavioral predictions."""
    pass


class ActionError(PterodactylGuardianError):
    """Exception raised when there is an error taking action on a threat."""
    pass


class QuarantineError(ActionError):
    """Exception raised when there is an error quarantining a file."""
    pass


class NotificationError(ActionError):
    """Exception raised when there is an error sending notifications."""
    pass


class ValidationError(PterodactylGuardianError):
    """Exception raised when validation of input data fails."""
    pass
