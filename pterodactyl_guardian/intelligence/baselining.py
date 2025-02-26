"""
Behavioral baselining for Pterodactyl Guardian SDK.

This module provides functionality to establish normal behavior patterns
for servers, users, and files, enabling more accurate anomaly detection.
"""

import logging
import time
import threading
import json
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from datetime import datetime, timedelta
import statistics
from collections import defaultdict


class Baseline:
    """Base class for behavioral baselines."""
    
    def __init__(
        self,
        id: str,
        creation_time: Optional[datetime] = None,
        last_updated: Optional[datetime] = None
    ):
        """
        Initialize baseline.
        
        Args:
            id: Baseline identifier
            creation_time: Creation timestamp
            last_updated: Last update timestamp
        """
        self.id = id
        self.creation_time = creation_time or datetime.now()
        self.last_updated = last_updated or self.creation_time
        self.data_points = 0
    
    def update(self, data: Any) -> None:
        """
        Update baseline with new data.
        
        Args:
            data: New data point
        """
        self.data_points += 1
        self.last_updated = datetime.now()
    
    def is_anomaly(self, data: Any) -> Tuple[bool, float, Optional[str]]:
        """
        Check if data point is anomalous.
        
        Args:
            data: Data point to check
            
        Returns:
            Tuple of (is_anomaly, anomaly_score, reason)
        """
        return False, 0.0, None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "creation_time": self.creation_time.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "data_points": self.data_points
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Baseline':
        """
        Create from dictionary.
        
        Args:
            data: Dictionary representation
            
        Returns:
            Baseline instance
        """
        creation_time = datetime.fromisoformat(data["creation_time"])
        last_updated = datetime.fromisoformat(data["last_updated"])
        
        baseline = cls(
            id=data["id"],
            creation_time=creation_time,
            last_updated=last_updated
        )
        baseline.data_points = data["data_points"]
        
        return baseline


class ResourceBaseline(Baseline):
    """Baseline for resource usage."""
    
    def __init__(
        self,
        id: str,
        creation_time: Optional[datetime] = None,
        last_updated: Optional[datetime] = None
    ):
        """
        Initialize resource baseline.
        
        Args:
            id: Baseline identifier
            creation_time: Creation timestamp
            last_updated: Last update timestamp
        """
        super().__init__(id, creation_time, last_updated)
        
        
        self.cpu_values: List[float] = []
        self.memory_values: List[float] = []
        self.disk_values: List[float] = []
        self.network_rx_values: List[float] = []
        self.network_tx_values: List[float] = []
        
      
        self.cpu_stats: Dict[str, float] = {}
        self.memory_stats: Dict[str, float] = {}
        self.disk_stats: Dict[str, float] = {}
        self.network_rx_stats: Dict[str, float] = {}
        self.network_tx_stats: Dict[str, float] = {}
    
    def update(self, data: Dict[str, float]) -> None:
        """
        Update resource baseline with new data.
        
        Args:
            data: Resource usage data
        """
        super().update(data)
        
       
        if "cpu" in data:
            self.cpu_values.append(data["cpu"])
        
        if "memory" in data:
            self.memory_values.append(data["memory"])
        
        if "disk" in data:
            self.disk_values.append(data["disk"])
        
        if "network_rx" in data:
            self.network_rx_values.append(data["network_rx"])
        
        if "network_tx" in data:
            self.network_tx_values.append(data["network_tx"])
        
    
        self._limit_history()
        

        self._calculate_statistics()
    
    def _limit_history(self) -> None:
        """Limit history to last 100 values."""
        max_history = 100
        
        if len(self.cpu_values) > max_history:
            self.cpu_values = self.cpu_values[-max_history:]
        
        if len(self.memory_values) > max_history:
            self.memory_values = self.memory_values[-max_history:]
        
        if len(self.disk_values) > max_history:
            self.disk_values = self.disk_values[-max_history:]
        
        if len(self.network_rx_values) > max_history:
            self.network_rx_values = self.network_rx_values[-max_history:]
        
        if len(self.network_tx_values) > max_history:
            self.network_tx_values = self.network_tx_values[-max_history:]
    
    def _calculate_statistics(self) -> None:
        """Calculate statistics for resource usage."""
       
        if self.cpu_values:
            self.cpu_stats = self._calculate_value_statistics(self.cpu_values)
        
     
        if self.memory_values:
            self.memory_stats = self._calculate_value_statistics(self.memory_values)
        
      
        if self.disk_values:
            self.disk_stats = self._calculate_value_statistics(self.disk_values)
        
       
        if self.network_rx_values:
            self.network_rx_stats = self._calculate_value_statistics(self.network_rx_values)
        
    
        if self.network_tx_values:
            self.network_tx_stats = self._calculate_value_statistics(self.network_tx_values)
    
    def _calculate_value_statistics(self, values: List[float]) -> Dict[str, float]:
        """
        Calculate statistics for a list of values.
        
        Args:
            values: List of values
            
        Returns:
            Dictionary of statistics
        """
        if not values:
            return {}
        
        stats = {}
        
        
        stats["min"] = min(values)
        stats["max"] = max(values)
        stats["mean"] = statistics.mean(values)
        
     
        sorted_values = sorted(values)
        stats["median"] = statistics.median(sorted_values)
        
        
        if len(values) > 1:
            stats["std_dev"] = statistics.stdev(values)
        else:
            stats["std_dev"] = 0.0
        
        
        if len(values) >= 4:
            q1_idx = len(values) // 4
            q3_idx = 3 * len(values) // 4
            stats["q1"] = sorted_values[q1_idx]
            stats["q3"] = sorted_values[q3_idx]
            stats["iqr"] = stats["q3"] - stats["q1"]
        else:
            stats["q1"] = stats["min"]
            stats["q3"] = stats["max"]
            stats["iqr"] = stats["max"] - stats["min"]
        
        return stats
    
    def is_anomaly(self, data: Dict[str, float]) -> Tuple[bool, float, Optional[str]]:
        """
        Check if resource usage data is anomalous.
        
        Args:
            data: Resource usage data
            
        Returns:
            Tuple of (is_anomaly, anomaly_score, reason)
        """
        
        if self.data_points < 10:
            return False, 0.0, None
        
        anomaly_score = 0.0
        reasons = []
        
       
        if "cpu" in data and self.cpu_stats:
            cpu_score = self._check_value_anomaly(data["cpu"], self.cpu_stats)
            if cpu_score > 0.7:
                reasons.append(f"CPU usage ({data['cpu']:.1f}%) abnormal")
                anomaly_score = max(anomaly_score, cpu_score)
         
        if "memory" in data and self.memory_stats:
            memory_score = self._check_value_anomaly(data["memory"], self.memory_stats)
            if memory_score > 0.7:
                reasons.append(f"Memory usage ({data['memory']:.1f}MB) abnormal")
                anomaly_score = max(anomaly_score, memory_score)
        
     
        if "disk" in data and self.disk_stats:
            disk_score = self._check_value_anomaly(data["disk"], self.disk_stats)
            if disk_score > 0.7:
                reasons.append(f"Disk usage ({data['disk']:.1f}MB) abnormal")
                anomaly_score = max(anomaly_score, disk_score)
        
       
        if "network_rx" in data and self.network_rx_stats:
            network_rx_score = self._check_value_anomaly(data["network_rx"], self.network_rx_stats)
            if network_rx_score > 0.7:
                reasons.append(f"Network RX ({data['network_rx']:.1f} bytes) abnormal")
                anomaly_score = max(anomaly_score, network_rx_score)
        
     
        if "network_tx" in data and self.network_tx_stats:
            network_tx_score = self._check_value_anomaly(data["network_tx"], self.network_tx_stats)
            if network_tx_score > 0.7:
                reasons.append(f"Network TX ({data['network_tx']:.1f} bytes) abnormal")
                anomaly_score = max(anomaly_score, network_tx_score)
        
       
        is_anomaly = anomaly_score > 0.7
        reason = ", ".join(reasons) if reasons else None
        
        return is_anomaly, anomaly_score, reason
    
    def _check_value_anomaly(self, value: float, stats: Dict[str, float]) -> float:
        """
        Check if a value is anomalous based on statistics.
        
        Args:
            value: Value to check
            stats: Statistics to compare against
            
        Returns:
            Anomaly score (0.0 to 1.0)
        """
     
        
      
        if "std_dev" in stats and stats["std_dev"] > 0:
            z_score = abs(value - stats["mean"]) / stats["std_dev"]
            
           
            z_anomaly = min(z_score / 3.0, 1.0)
        else:
            z_anomaly = 0.0
        
    
        if "q1" in stats and "q3" in stats and "iqr" in stats and stats["iqr"] > 0:
           
            iqr_factor = 1.5
            lower_bound = stats["q1"] - (iqr_factor * stats["iqr"])
            upper_bound = stats["q3"] + (iqr_factor * stats["iqr"])
            
            if value < lower_bound:
                
                distance = (lower_bound - value) / (stats["iqr"] * iqr_factor)
                iqr_anomaly = min(distance, 1.0)
            elif value > upper_bound:
                
                distance = (value - upper_bound) / (stats["iqr"] * iqr_factor)
                iqr_anomaly = min(distance, 1.0)
            else:
             
                iqr_anomaly = 0.0
        else:
            iqr_anomaly = 0.0
 
        if "max" in stats and stats["max"] > 0:
            if value > stats["max"]:
                relative_increase = (value - stats["max"]) / stats["max"]
                max_anomaly = min(relative_increase, 1.0)
            else:
                max_anomaly = 0.0
        else:
            max_anomaly = 0.0

        weights = {
            "z": 0.4,    
            "iqr": 0.4,   
            "max": 0.2    
        }
        
        anomaly_score = (
            (z_anomaly * weights["z"]) +
            (iqr_anomaly * weights["iqr"]) +
            (max_anomaly * weights["max"])
        )
        
        return anomaly_score
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = super().to_dict()
        
  
        result.update({
            "cpu_values": self.cpu_values,
            "memory_values": self.memory_values,
            "disk_values": self.disk_values,
            "network_rx_values": self.network_rx_values,
            "network_tx_values": self.network_tx_values,
            "cpu_stats": self.cpu_stats,
            "memory_stats": self.memory_stats,
            "disk_stats": self.disk_stats,
            "network_rx_stats": self.network_rx_stats,
            "network_tx_stats": self.network_tx_stats
        })
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourceBaseline':
        """
        Create from dictionary.
        
        Args:
            data: Dictionary representation
            
        Returns:
            ResourceBaseline instance
        """
        baseline = super().from_dict(data)
        

        baseline.cpu_values = data.get("cpu_values", [])
        baseline.memory_values = data.get("memory_values", [])
        baseline.disk_values = data.get("disk_values", [])
        baseline.network_rx_values = data.get("network_rx_values", [])
        baseline.network_tx_values = data.get("network_tx_values", [])
        baseline.cpu_stats = data.get("cpu_stats", {})
        baseline.memory_stats = data.get("memory_stats", {})
        baseline.disk_stats = data.get("disk_stats", {})
        baseline.network_rx_stats = data.get("network_rx_stats", {})
        baseline.network_tx_stats = data.get("network_tx_stats", {})
        
        return baseline


class UserActivityBaseline(Baseline):
    """Baseline for user activity patterns."""
    
    def __init__(
        self,
        id: str,
        creation_time: Optional[datetime] = None,
        last_updated: Optional[datetime] = None
    ):
        """
        Initialize user activity baseline.
        
        Args:
            id: Baseline identifier
            creation_time: Creation timestamp
            last_updated: Last update timestamp
        """
        super().__init__(id, creation_time, last_updated)

        self.hourly_activity = [0] * 24
        
        self.daily_activity = [0] * 7
      
        self.activity_types: Dict[str, int] = {}
        
        self.ip_addresses: Dict[str, int] = {}
        

        self.request_patterns: Dict[str, int] = {}
    
    def update(self, data: Dict[str, Any]) -> None:
        """
        Update user activity baseline with new data.
        
        Args:
            data: User activity data
        """
        super().update(data)
        
      
        if "timestamp" in data:
            timestamp = data["timestamp"]
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    timestamp = datetime.now()
            
            hour = timestamp.hour
            day = timestamp.weekday()
            
            self.hourly_activity[hour] += 1
            self.daily_activity[day] += 1
        
      
        if "type" in data:
            activity_type = data["type"]
            self.activity_types[activity_type] = self.activity_types.get(activity_type, 0) + 1
        
  
        if "ip_address" in data:
            ip_address = data["ip_address"]
            self.ip_addresses[ip_address] = self.ip_addresses.get(ip_address, 0) + 1
        
    
        if "request_path" in data:
            request_path = data["request_path"]
            self.request_patterns[request_path] = self.request_patterns.get(request_path, 0) + 1
    
    def is_anomaly(self, data: Dict[str, Any]) -> Tuple[bool, float, Optional[str]]:
        """
        Check if user activity data is anomalous.
        
        Args:
            data: User activity data
            
        Returns:
            Tuple of (is_anomaly, anomaly_score, reason)
        """
       
        if self.data_points < 50:
            return False, 0.0, None
        
        anomaly_score = 0.0
        reasons = []
        
       
        if "timestamp" in data:
            timestamp = data["timestamp"]
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    timestamp = datetime.now()
            
            hour = timestamp.hour
            day = timestamp.weekday()
            
           
            hourly_anomaly = self._check_hourly_anomaly(hour)
            if hourly_anomaly > 0.7:
                reasons.append(f"Unusual hour of activity ({hour})")
                anomaly_score = max(anomaly_score, hourly_anomaly)
            
           
            daily_anomaly = self._check_daily_anomaly(day)
            if daily_anomaly > 0.7:
                reasons.append(f"Unusual day of activity ({day})")
                anomaly_score = max(anomaly_score, daily_anomaly)
        
      
        if "type" in data:
            activity_type = data["type"]
            type_anomaly = self._check_activity_type_anomaly(activity_type)
            if type_anomaly > 0.7:
                reasons.append(f"Unusual activity type ({activity_type})")
                anomaly_score = max(anomaly_score, type_anomaly)
        
     
        if "ip_address" in data:
            ip_address = data["ip_address"]
            ip_anomaly = self._check_ip_anomaly(ip_address)
            if ip_anomaly > 0.7:
                reasons.append(f"Unusual IP address ({ip_address})")
                anomaly_score = max(anomaly_score, ip_anomaly)
        
        
        if "request_path" in data:
            request_path = data["request_path"]
            request_anomaly = self._check_request_anomaly(request_path)
            if request_anomaly > 0.7:
                reasons.append(f"Unusual request path ({request_path})")
                anomaly_score = max(anomaly_score, request_anomaly)
        

        is_anomaly = anomaly_score > 0.7
        reason = ", ".join(reasons) if reasons else None
        
        return is_anomaly, anomaly_score, reason
    
    def _check_hourly_anomaly(self, hour: int) -> float:
        """
        Check if activity during an hour is anomalous.
        
        Args:
            hour: Hour of day (0-23)
            
        Returns:
            Anomaly score (0.0 to 1.0)
        """
      
        total_activity = sum(self.hourly_activity)
        if total_activity == 0:
            return 0.0
        
     
        hour_probability = self.hourly_activity[hour] / total_activity
        
    
        if hour_probability < 0.01:
            return 1.0
        elif hour_probability < 0.05:
            return 0.8
        elif hour_probability < 0.1:
            return 0.5
        else:
            return 0.0
    
    def _check_daily_anomaly(self, day: int) -> float:
        """
        Check if activity on a day is anomalous.
        
        Args:
            day: Day of week (0-6, where 0 is Monday)
            
        Returns:
            Anomaly score (0.0 to 1.0)
        """
     
        total_activity = sum(self.daily_activity)
        if total_activity == 0:
            return 0.0
        
      
        day_probability = self.daily_activity[day] / total_activity
        
     
        if day_probability < 0.01:
            return 1.0
        elif day_probability < 0.05:
            return 0.8
        elif day_probability < 0.1:
            return 0.5
        else:
            return 0.0
    
    def _check_activity_type_anomaly(self, activity_type: str) -> float:
        """
        Check if an activity type is anomalous.
        
        Args:
            activity_type: Type of activity
            
        Returns:
            Anomaly score (0.0 to 1.0)
        """
       
        if activity_type not in self.activity_types:
            return 1.0
        
   
        total_activities = sum(self.activity_types.values())
        type_frequency = self.activity_types[activity_type] / total_activities
        

        if type_frequency < 0.01:
            return 0.9
        elif type_frequency < 0.05:
            return 0.7
        elif type_frequency < 0.1:
            return 0.4
        else:
            return 0.0
    
    def _check_ip_anomaly(self, ip_address: str) -> float:
        """
        Check if an IP address is anomalous.
        
        Args:
            ip_address: IP address
            
        Returns:
            Anomaly score (0.0 to 1.0)
        """
     
        if ip_address not in self.ip_addresses:
            return 0.9
        
      
        total_ips = sum(self.ip_addresses.values())
        ip_frequency = self.ip_addresses[ip_address] / total_ips
        
       
        if ip_frequency < 0.01:
            return 0.8
        elif ip_frequency < 0.05:
            return 0.6
        elif ip_frequency < 0.1:
            return 0.3
        else:
            return 0.0
    
    def _check_request_anomaly(self, request_path: str) -> float:
        """
        Check if a request path is anomalous.
        
        Args:
            request_path: Request path
            
        Returns:
            Anomaly score (0.0 to 1.0)
        """
      
        if request_path not in self.request_patterns:
         
            similar_path = self._find_similar_request_path(request_path)
            if similar_path:
                return self._check_request_anomaly(similar_path) * 0.5
            return 0.7
        
      
        total_requests = sum(self.request_patterns.values())
        request_frequency = self.request_patterns[request_path] / total_requests
        

        if request_frequency < 0.01:
            return 0.7
        elif request_frequency < 0.05:
            return 0.5
        elif request_frequency < 0.1:
            return 0.2
        else:
            return 0.0
    
    def _find_similar_request_path(self, request_path: str) -> Optional[str]:
        """
        Find a similar request path in the baseline.
        
        Args:
            request_path: Request path to match
            
        Returns:
            Similar request path or None
        """
       
        normalized_path = re.sub(r'\d+', 'X', request_path)
        
        for path in self.request_patterns:
            normalized_known_path = re.sub(r'\d+', 'X', path)
            if normalized_path == normalized_known_path:
                return path
        
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = super().to_dict()
        
       
        result.update({
            "hourly_activity": self.hourly_activity,
            "daily_activity": self.daily_activity,
            "activity_types": self.activity_types,
            "ip_addresses": self.ip_addresses,
            "request_patterns": self.request_patterns
        })
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserActivityBaseline':
        """
        Create from dictionary.
        
        Args:
            data: Dictionary representation
            
        Returns:
            UserActivityBaseline instance
        """
        baseline = super().from_dict(data)
      
        baseline.hourly_activity = data.get("hourly_activity", [0] * 24)
        baseline.daily_activity = data.get("daily_activity", [0] * 7)
        baseline.activity_types = data.get("activity_types", {})
        baseline.ip_addresses = data.get("ip_addresses", {})
        baseline.request_patterns = data.get("request_patterns", {})
        
        return baseline


class BehavioralBaselining:
    """
    System for establishing and using behavioral baselines.
    """
    
    def __init__(
        self,
        storage=None,
        anomaly_threshold: float = 0.7,
        minimum_data_points: int = 50,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize behavioral baselining.
        
        Args:
            storage: Storage manager
            anomaly_threshold: Threshold for anomaly detection
            minimum_data_points: Minimum data points for reliable detection
            logger: Logger instance
        """
        self.storage = storage
        self.anomaly_threshold = anomaly_threshold
        self.minimum_data_points = minimum_data_points
        self.logger = logger or logging.getLogger(__name__)
        
      
        self._baselines: Dict[str, Dict[str, Baseline]] = {
            "resource": {},
            "user_activity": {}
        }
        
       
        self._lock = threading.RLock()
        
       
        self._load_baselines()
    
    def _load_baselines(self) -> None:
        """Load baselines from storage."""
        if not self.storage:
            return
        
        try:
            
            resource_baselines = self.storage.get_setting("resource_baselines", {})
            for id, data in resource_baselines.items():
                self._baselines["resource"][id] = ResourceBaseline.from_dict(data)
            
            
            user_activity_baselines = self.storage.get_setting("user_activity_baselines", {})
            for id, data in user_activity_baselines.items():
                self._baselines["user_activity"][id] = UserActivityBaseline.from_dict(data)
            
            self.logger.info(
                f"Loaded {len(self._baselines['resource'])} resource baselines "
                f"and {len(self._baselines['user_activity'])} user activity baselines"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to load baselines: {e}")
    
    def _save_baselines(self) -> None:
        """Save baselines to storage."""
        if not self.storage:
            return
        
        try:
            with self._lock:
         
                resource_baselines = {
                    id: baseline.to_dict()
                    for id, baseline in self._baselines["resource"].items()
                }
                
               
                user_activity_baselines = {
                    id: baseline.to_dict()
                    for id, baseline in self._baselines["user_activity"].items()
                }
                
               
                self.storage.set_setting("resource_baselines", resource_baselines)
                self.storage.set_setting("user_activity_baselines", user_activity_baselines)
                
        except Exception as e:
            self.logger.error(f"Failed to save baselines: {e}")
    
    def update_resource_baseline(self, server_id: str, data: Dict[str, float]) -> None:
        """
        Update resource baseline for a server.
        
        Args:
            server_id: Server identifier
            data: Resource usage data
        """
        with self._lock:
       
            if server_id not in self._baselines["resource"]:
                self._baselines["resource"][server_id] = ResourceBaseline(server_id)
            
           
            self._baselines["resource"][server_id].update(data)
            
        
            if self._baselines["resource"][server_id].data_points % 10 == 0:
                self._save_baselines()
    
    def check_resource_anomaly(
        self,
        server_id: str,
        data: Dict[str, float]
    ) -> Tuple[bool, float, Optional[str]]:
        """
        Check if resource usage is anomalous.
        
        Args:
            server_id: Server identifier
            data: Resource usage data
            
        Returns:
            Tuple of (is_anomaly, anomaly_score, reason)
        """
        with self._lock:
            
            if server_id not in self._baselines["resource"]:
                return False, 0.0, None
            
           
            baseline = self._baselines["resource"][server_id]
            if baseline.data_points < self.minimum_data_points:
                return False, 0.0, None
            
 
            return baseline.is_anomaly(data)
    
    def update_user_activity_baseline(self, user_id: str, data: Dict[str, Any]) -> None:
        """
        Update user activity baseline.
        
        Args:
            user_id: User identifier
            data: User activity data
        """
        with self._lock:
         
            if user_id not in self._baselines["user_activity"]:
                self._baselines["user_activity"][user_id] = UserActivityBaseline(user_id)
            
            self._baselines["user_activity"][user_id].update(data)
            
            
            if self._baselines["user_activity"][user_id].data_points % 10 == 0:
                self._save_baselines()
    
    def check_user_activity_anomaly(
        self,
        user_id: str,
        data: Dict[str, Any]
    ) -> Tuple[bool, float, Optional[str]]:
        """
        Check if user activity is anomalous.
        
        Args:
            user_id: User identifier
            data: User activity data
            
        Returns:
            Tuple of (is_anomaly, anomaly_score, reason)
        """
        with self._lock:
           
            if user_id not in self._baselines["user_activity"]:
                return False, 0.0, None
            
           
            baseline = self._baselines["user_activity"][user_id]
            if baseline.data_points < self.minimum_data_points:
                return False, 0.0, None
            
           
            return baseline.is_anomaly(data)
    
    def get_baseline_status(self, baseline_type: str, id: str) -> Dict[str, Any]:
        """
        Get status of a baseline.
        
        Args:
            baseline_type: Type of baseline ("resource" or "user_activity")
            id: Baseline identifier
            
        Returns:
            Baseline status
        """
        with self._lock:
            if baseline_type not in self._baselines or id not in self._baselines[baseline_type]:
                return {
                    "exists": False,
                    "data_points": 0,
                    "ready": False
                }
            
            baseline = self._baselines[baseline_type][id]
            return {
                "exists": True,
                "data_points": baseline.data_points,
                "ready": baseline.data_points >= self.minimum_data_points,
                "created_at": baseline.creation_time.isoformat(),
                "last_updated": baseline.last_updated.isoformat()
            }
    
    def reset_baseline(self, baseline_type: str, id: str) -> bool:
        """
        Reset a baseline.
        
        Args:
            baseline_type: Type of baseline ("resource" or "user_activity")
            id: Baseline identifier
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            if baseline_type not in self._baselines or id not in self._baselines[baseline_type]:
                return False
            
            
            del self._baselines[baseline_type][id]
            
           
            self._save_baselines()
            
            return True
