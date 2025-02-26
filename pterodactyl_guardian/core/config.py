"""
Configuration management for Pterodactyl Guardian SDK.

This module provides configuration management and validation
for the SDK, ensuring that all options are properly validated.
"""

import os
import logging
from typing import Dict, List, Any, Optional, Union, Set
import json

from ..exceptions import ConfigurationError
from ..enums import (
    DetectionModules,
    AnalysisLevel,
    LearningMode,
    StorageEngine,
    QuarantineAction,
    APIType
)


class ConfigManager:
    """
    Configuration manager for Pterodactyl Guardian SDK.
    """
    
    
    _defaults = {
        n
        "panel_url": None,  
        "api_key": None,    
        "api_type": APIType.APPLICATION.value,
        "api_timeout": 30,
        "api_max_retries": 3,
        "api_retry_delay": 2,
        
       
        "enabled_modules": DetectionModules.all(),
        "detection_thresholds": {
            DetectionModules.AUTOMATION.value: 0.6,
            DetectionModules.NETWORK.value: 0.7,
            DetectionModules.RESOURCE.value: 0.7,
            DetectionModules.SPAM.value: 0.6,
            DetectionModules.DATA_HARVESTING.value: 0.7,
            DetectionModules.GAME_SERVER.value: 0.6,
            DetectionModules.WEB_SERVER.value: 0.7,
            DetectionModules.INFRASTRUCTURE.value: 0.8,
            DetectionModules.SECURITY.value: 0.7,
            DetectionModules.OBFUSCATION.value: 0.6
        },
        "custom_patterns": {},  
        
        
        "analysis_level": AnalysisLevel.STANDARD.value,
        "learning_mode": LearningMode.BALANCED.value,
        "adaptive_learning": True,
        
       
        "storage_engine": StorageEngine.SQLITE.value,
        "storage_path": None,  
        "data_retention_days": 30,
        "postgresql_dsn": None,  
        
        
        "max_cpu_percent": 30,
        "max_memory_mb": 250,
        "scan_threads": 2,
        
        
        "check_interval_hours": None,
        "check_interval_minutes": 60,
        "file_patterns": ["*.php", "*.js", "*.py", "*.sh", "*.html"],
        "resource_thresholds": {
            "cpu": 90.0,
            "memory": 85.0,
            "disk": 95.0,
            "network": 10000000.0  
        },
        
        
        "quarantine_action": QuarantineAction.RENAME.value,
        "quarantine_directory": ".quarantine",
        "alert_webhook": None,
        
        
        "log_level": "INFO",
        "log_file": None,
        "log_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    }
    
    def __init__(self, **kwargs):
        """
        Initialize the configuration manager.
        
        Args:
            **kwargs: Configuration options
        """
        self._config = self._defaults.copy()
        self.update(**kwargs)
        
       
        if not self._config["storage_path"]:
            home_dir = os.path.expanduser("~")
            self._config["storage_path"] = os.path.join(home_dir, ".pterodactyl_guardian")
    
    def update(self, **kwargs):
        """
        Update configuration with new values.
        
        Args:
            **kwargs: Configuration options to update
            
        Raises:
            ConfigurationError: If validation fails
        """
        
        for key, value in kwargs.items():
            if key in self._config:
                self._config[key] = value
            else:
                raise ConfigurationError(f"Unknown configuration option: {key}")
        
        
        self.validate()
    
    def validate(self):
        """
        Validate the configuration.
        
        Raises:
            ConfigurationError: If validation fails
        """
        
        if not self._config["panel_url"]:
            raise ConfigurationError("panel_url is required")
        if not self._config["api_key"]:
            raise ConfigurationError("api_key is required")
        
        
        if self._config["panel_url"]:
            self._config["panel_url"] = self._config["panel_url"].rstrip("/")
            if not (self._config["panel_url"].startswith("http://") or 
                    self._config["panel_url"].startswith("https://")):
                self._config["panel_url"] = f"https://{self._config['panel_url']}"
        
        
        valid_api_types = [api_type.value for api_type in APIType]
        if self._config["api_type"] not in valid_api_types:
            raise ConfigurationError(
                f"Invalid api_type: {self._config['api_type']}. "
                f"Must be one of: {', '.join(valid_api_types)}"
            )
        
        
        valid_storage_engines = [engine.value for engine in StorageEngine]
        if self._config["storage_engine"] not in valid_storage_engines:
            raise ConfigurationError(
                f"Invalid storage_engine: {self._config['storage_engine']}. "
                f"Must be one of: {', '.join(valid_storage_engines)}"
            )
        
       
        if (self._config["storage_engine"] == StorageEngine.POSTGRESQL.value and
                not self._config["postgresql_dsn"]):
            raise ConfigurationError("postgresql_dsn is required when using PostgreSQL storage engine")
        
        
        valid_analysis_levels = [level.value for level in AnalysisLevel]
        if self._config["analysis_level"] not in valid_analysis_levels:
            raise ConfigurationError(
                f"Invalid analysis_level: {self._config['analysis_level']}. "
                f"Must be one of: {', '.join(valid_analysis_levels)}"
            )
        
        
        valid_learning_modes = [mode.value for mode in LearningMode]
        if self._config["learning_mode"] not in valid_learning_modes:
            raise ConfigurationError(
                f"Invalid learning_mode: {self._config['learning_mode']}. "
                f"Must be one of: {', '.join(valid_learning_modes)}"
            )
        
        
        if self._config["max_cpu_percent"] <= 0 or self._config["max_cpu_percent"] > 100:
            raise ConfigurationError("max_cpu_percent must be between 1 and 100")
        if self._config["max_memory_mb"] <= 0:
            raise ConfigurationError("max_memory_mb must be greater than 0")
        if self._config["scan_threads"] <= 0:
            raise ConfigurationError("scan_threads must be greater than 0")
        
        
        if not (self._config["check_interval_hours"] or self._config["check_interval_minutes"]):
            self._config["check_interval_minutes"] = 60
        if self._config["check_interval_hours"] and self._config["check_interval_hours"] <= 0:
            raise ConfigurationError("check_interval_hours must be greater than 0")
        if self._config["check_interval_minutes"] and self._config["check_interval_minutes"] <= 0:
            raise ConfigurationError("check_interval_minutes must be greater than 0")
        
        
        valid_modules = DetectionModules.all()
        for module in self._config["enabled_modules"]:
            if module not in valid_modules:
                raise ConfigurationError(
                    f"Invalid module: {module}. "
                    f"Must be one of: {', '.join(valid_modules)}"
                )
        
        
        for module, threshold in self._config["detection_thresholds"].items():
            if threshold < 0 or threshold > 1:
                raise ConfigurationError(
                    f"Invalid threshold for {module}: {threshold}. "
                    "Must be between 0 and 1"
                )
        
        
        for module in valid_modules:
            if module not in self._config["detection_thresholds"]:
                self._config["detection_thresholds"][module] = 0.7
        
        
        valid_quarantine_actions = [action.value for action in QuarantineAction]
        if self._config["quarantine_action"] not in valid_quarantine_actions:
            raise ConfigurationError(
                f"Invalid quarantine_action: {self._config['quarantine_action']}. "
                f"Must be one of: {', '.join(valid_quarantine_actions)}"
            )
        
        
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self._config["log_level"] not in valid_log_levels:
            raise ConfigurationError(
                f"Invalid log_level: {self._config['log_level']}. "
                f"Must be one of: {', '.join(valid_log_levels)}"
            )
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        return self._config.get(key, default)
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get all configuration values.
        
        Returns:
            Dictionary of all configuration values
        """
        return self._config.copy()
    
    def get_enabled_modules(self) -> List[str]:
        """
        Get a list of enabled detection modules.
        
        Returns:
            List of enabled module names
        """
        return self._config["enabled_modules"]
    
    def get_threshold(self, module: str) -> float:
        """
        Get the detection threshold for a module.
        
        Args:
            module: Module name
            
        Returns:
            Detection threshold
        """
        return self._config["detection_thresholds"].get(module, 0.7)
    
    def get_resource_threshold(self, resource: str) -> float:
        """
        Get the threshold for a resource type.
        
        Args:
            resource: Resource type (cpu, memory, disk, network)
            
        Returns:
            Resource threshold
        """
        return self._config["resource_thresholds"].get(resource, 90.0)
    
    def save(self, filepath: Optional[str] = None) -> None:
        """
        Save the configuration to a file.
        
        Args:
            filepath: Path to the configuration file
        """
        if not filepath:
            filepath = os.path.join(self._config["storage_path"], "config.json")
        
       
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        
        with open(filepath, "w") as f:
            json.dump(self._config, f, indent=2)
    
    @classmethod
    def load(cls, filepath: str) -> 'ConfigManager':
        """
        Load configuration from a file.
        
        Args:
            filepath: Path to the configuration file
            
        Returns:
            ConfigManager instance
        """
        with open(filepath, "r") as f:
            config = json.load(f)
        
        return cls(**config)
    
    def setup_logging(self) -> logging.Logger:
        """
        Set up logging based on configuration.
        
        Returns:
            Logger instance
        """
        logger = logging.getLogger("pterodactyl_guardian")
        logger.setLevel(getattr(logging, self._config["log_level"]))
        
        
        formatter = logging.Formatter(self._config["log_format"])
        
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
       
        if self._config["log_file"]:
            
            log_dir = os.path.dirname(self._config["log_file"])
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
                
            
            file_handler = logging.FileHandler(self._config["log_file"])
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
