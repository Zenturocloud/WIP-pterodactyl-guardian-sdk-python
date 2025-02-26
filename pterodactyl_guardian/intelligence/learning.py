"""
Adaptive learning system for Pterodactyl Guardian SDK.

This module provides the adaptive learning capabilities that enable the system
to improve detection accuracy over time based on feedback and observations.
"""

import logging
import time
import threading
import json
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from datetime import datetime, timedelta
import math

from ..enums import LearningMode, DetectionModules
from ..exceptions import LearningError


class PatternWeight:
    """Weight information for a detection pattern."""
    
    def __init__(
        self,
        pattern_id: str,
        initial_weight: float = 1.0,
        positive_evidence: int = 0,
        negative_evidence: int = 0,
        last_updated: Optional[datetime] = None
    ):
        """
        Initialize pattern weight.
        
        Args:
            pattern_id: Pattern identifier
            initial_weight: Initial weight value
            positive_evidence: Count of positive evidence
            negative_evidence: Count of negative evidence
            last_updated: Last update timestamp
        """
        self.pattern_id = pattern_id
        self.initial_weight = initial_weight
        self.current_weight = initial_weight
        self.positive_evidence = positive_evidence
        self.negative_evidence = negative_evidence
        self.last_updated = last_updated or datetime.now()
        self.confidence = 0.5  
    
    def update(self, positive: bool = True, strength: float = 1.0) -> None:
        """
        Update weight based on evidence.
        
        Args:
            positive: Whether the evidence is positive (true positive)
            strength: Evidence strength (0.0 to 1.0)
        """

        if positive:
            self.positive_evidence += 1
        else:
            self.negative_evidence += 1
        
       
        if positive:
           
            delta = strength * (2.0 - self.current_weight) * 0.1
            self.current_weight = min(2.0, self.current_weight + delta)
        else:
            
            delta = strength * (self.current_weight - 0.1) * 0.2
            self.current_weight = max(0.1, self.current_weight - delta)
        
        
        total_evidence = self.positive_evidence + self.negative_evidence
        if total_evidence > 0:
            
            evidence_factor = min(total_evidence / 10.0, 1.0)
            
            positive_ratio = self.positive_evidence / total_evidence
            self.confidence = positive_ratio * evidence_factor + 0.5 * (1 - evidence_factor)
        
        self.last_updated = datetime.now()
    
    def reset(self) -> None:
        """Reset weight to initial value."""
        self.current_weight = self.initial_weight
        self.positive_evidence = 0
        self.negative_evidence = 0
        self.confidence = 0.5
        self.last_updated = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "pattern_id": self.pattern_id,
            "initial_weight": self.initial_weight,
            "current_weight": self.current_weight,
            "positive_evidence": self.positive_evidence,
            "negative_evidence": self.negative_evidence,
            "last_updated": self.last_updated.isoformat(),
            "confidence": self.confidence
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PatternWeight':
        """
        Create from dictionary.
        
        Args:
            data: Dictionary representation
            
        Returns:
            PatternWeight instance
        """
        last_updated = None
        if "last_updated" in data:
            try:
                last_updated = datetime.fromisoformat(data["last_updated"])
            except (ValueError, TypeError):
                last_updated = datetime.now()
        
        return cls(
            pattern_id=data["pattern_id"],
            initial_weight=data.get("initial_weight", 1.0),
            positive_evidence=data.get("positive_evidence", 0),
            negative_evidence=data.get("negative_evidence", 0),
            last_updated=last_updated
        )


class AdaptiveLearning:
    """
    Adaptive learning system for improving detection accuracy.
    """
    
    def __init__(
        self,
        storage=None,
        mode: str = LearningMode.BALANCED.value,
        decay_days: int = 30,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the adaptive learning system.
        
        Args:
            storage: Storage manager for persisting learning data
            mode: Learning mode (conservative, balanced, aggressive)
            decay_days: Number of days for weight decay
            logger: Logger instance
        """
        self.storage = storage
        self.mode = mode
        self.decay_days = decay_days
        self.logger = logger or logging.getLogger(__name__)
        
       
        self.learning_rates = {
            LearningMode.CONSERVATIVE.value: 0.05,  
            LearningMode.BALANCED.value: 0.1,     
            LearningMode.AGGRESSIVE.value: 0.2     
        }
        
       
        self._weights: Dict[str, Dict[str, PatternWeight]] = {}
        
        
        self._threshold_adjustments: Dict[str, float] = {}
        
       
        self._module_scores: Dict[str, float] = {}
        
       
        self._lock = threading.RLock()
        
       
        self._initialize_weights()
        
        
        self._decay_thread = threading.Thread(target=self._decay_loop)
        self._decay_thread.daemon = True
        self._decay_thread.start()
    
    def _initialize_weights(self) -> None:
        """Initialize pattern weights."""
        with self._lock:
           
            self._weights.clear()
            
            
            for module in DetectionModules.all():
                self._module_scores[module] = 0.5  
            
           
            if self.storage:
                try:
                  
                    stored_weights = self.storage.get_setting("pattern_weights", {})
                    for module, weights in stored_weights.items():
                        self._weights[module] = {}
                        for pattern_id, weight_data in weights.items():
                            self._weights[module][pattern_id] = PatternWeight.from_dict(weight_data)
                    
                   
                    self._threshold_adjustments = self.storage.get_setting("threshold_adjustments", {})
                    
                   
                    stored_scores = self.storage.get_setting("module_scores", {})
                    for module, score in stored_scores.items():
                        self._module_scores[module] = score
                    
                    self.logger.info("Loaded adaptive learning data from storage")
                    
                except Exception as e:
                    self.logger.error(f"Failed to load learning data: {e}")
                   
    
    def get_pattern_weight(self, module: str, pattern_id: str) -> float:
        """
        Get the current weight for a pattern.
        
        Args:
            module: Detection module
            pattern_id: Pattern identifier
            
        Returns:
            Current weight value
        """
        with self._lock:
            
            if module not in self._weights:
                self._weights[module] = {}
            
           
            if pattern_id not in self._weights[module]:
                self._weights[module][pattern_id] = PatternWeight(pattern_id)
            
            return self._weights[module][pattern_id].current_weight
    
    def get_threshold_adjustment(self, module: str) -> float:
        """
        Get the threshold adjustment for a module.
        
        Args:
            module: Detection module
            
        Returns:
            Threshold adjustment value (-0.2 to 0.2)
        """
        with self._lock:
            return self._threshold_adjustments.get(module, 0.0)
    
    def get_detection_confidence(self, module: str, pattern_id: str) -> float:
        """
        Get the confidence score for a pattern detection.
        
        Args:
            module: Detection module
            pattern_id: Pattern identifier
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        with self._lock:
            
            if module not in self._weights:
                return 0.5  
            
            
            if pattern_id in self._weights[module]:
                return self._weights[module][pattern_id].confidence
            
            return 0.5  
    
    def process_feedback(
        self,
        module: str,
        pattern_id: Optional[str] = None,
        detection_id: Optional[str] = None,
        false_positive: bool = False,
        notes: Optional[str] = None
    ) -> None:
        """
        Process feedback for a detection.
        
        Args:
            module: Detection module
            pattern_id: Pattern identifier (optional)
            detection_id: Detection identifier (optional)
            false_positive: Whether detection was a false positive
            notes: Additional notes
        """
        with self._lock:
            
            learning_rate = self.learning_rates.get(self.mode, 0.1)
            
            
            if pattern_id:
                self._process_pattern_feedback(module, pattern_id, not false_positive, learning_rate)
            
           
            if detection_id:
                self._process_detection_feedback(module, detection_id, not false_positive, learning_rate)
            
           
            self._process_module_feedback(module, not false_positive, learning_rate)
            
            
            self._save_learning_data()
    
    def _process_pattern_feedback(
        self,
        module: str,
        pattern_id: str,
        positive: bool,
        learning_rate: float
    ) -> None:
        """
        Process feedback for a specific pattern.
        
        Args:
            module: Detection module
            pattern_id: Pattern identifier
            positive: Whether detection was correct
            learning_rate: Learning rate
        """
       
        if module not in self._weights:
            self._weights[module] = {}
        
       
        if pattern_id not in self._weights[module]:
            self._weights[module][pattern_id] = PatternWeight(pattern_id)
        
        
        self._weights[module][pattern_id].update(positive, learning_rate)
        
        self.logger.debug(
            f"Updated pattern weight for {module}:{pattern_id} "
            f"to {self._weights[module][pattern_id].current_weight:.2f}"
        )
    
    def _process_detection_feedback(
        self,
        module: str,
        detection_id: str,
        positive: bool,
        learning_rate: float
    ) -> None:
        """
        Process feedback for a detection.
        
        Args:
            module: Detection module
            detection_id: Detection identifier
            positive: Whether detection was correct
            learning_rate: Learning rate
        """
        
        if not self.storage:
            return
        
        try:
            detection = self.storage.get_detection(detection_id)
            if not detection:
                self.logger.warning(f"Detection {detection_id} not found")
                return
            

            self.storage.update_detection_review(detection_id, not positive)
            
        
            if "details" in detection and isinstance(detection["details"], dict):
                for pattern_id in detection["details"].get("matched_patterns", []):
                    self._process_pattern_feedback(module, pattern_id, positive, learning_rate)
            
        except Exception as e:
            self.logger.error(f"Error processing detection feedback: {e}")
    
    def _process_module_feedback(
        self,
        module: str,
        positive: bool,
        learning_rate: float
    ) -> None:
        """
        Process feedback for a module.
        
        Args:
            module: Detection module
            positive: Whether detection was correct
            learning_rate: Learning rate
        """
        
        current_score = self._module_scores.get(module, 0.5)
        
        if positive:
            
            delta = learning_rate * (1.0 - current_score)
            new_score = current_score + delta
        else:
            
            delta = learning_rate * current_score
            new_score = current_score - delta
        
        self._module_scores[module] = max(0.0, min(1.0, new_score))
        
        
        if self._module_scores[module] > 0.7:
            self._threshold_adjustments[module] = -0.1  
        elif self._module_scores[module] < 0.3:
            self._threshold_adjustments[module] = 0.1   
        else:
            self._threshold_adjustments[module] = 0.0   
        
        self.logger.debug(
            f"Updated module score for {module} to {self._module_scores[module]:.2f} "
            f"(threshold adjustment: {self._threshold_adjustments[module]:.2f})"
        )
    
    def _decay_loop(self) -> None:
        """Loop for periodically decaying weights."""
        while True:
            
            time.sleep(24 * 60 * 60)
            
            try:
                self._decay_weights()
                self._save_learning_data()
            except Exception as e:
                self.logger.error(f"Error in weight decay: {e}")
    
    def _decay_weights(self) -> None:
        """Decay weights over time to forget old feedback."""
        with self._lock:
            now = datetime.now()
            decay_threshold = now - timedelta(days=self.decay_days)
            
            for module in self._weights:
                for pattern_id, weight in list(self._weights[module].items()):
                    
                    if weight.last_updated > decay_threshold:
                        continue
                    
                
                    age_days = (now - weight.last_updated).days
                    decay_factor = age_days / self.decay_days
                    
                    
                    diff = weight.current_weight - weight.initial_weight
                    decay = diff * decay_factor * 0.1  
                    
                    weight.current_weight -= decay
                    
                   
                    if (weight.confidence < 0.3
                            and abs(weight.current_weight - weight.initial_weight) < 0.05):
                        del self._weights[module][pattern_id]
                    
                    self.logger.debug(
                        f"Decayed weight for {module}:{pattern_id} "
                        f"by {decay:.3f} to {weight.current_weight:.2f}"
                    )
    
    def _save_learning_data(self) -> None:
        """Save learning data to storage."""
        if not self.storage:
            return
        
        try:
            with self._lock:
                
                weights_dict = {}
                for module, weights in self._weights.items():
                    weights_dict[module] = {
                        pattern_id: weight.to_dict()
                        for pattern_id, weight in weights.items()
                    }
                
               
                self.storage.set_setting("pattern_weights", weights_dict)
                
                
                self.storage.set_setting("threshold_adjustments", self._threshold_adjustments)
                
                
                self.storage.set_setting("module_scores", self._module_scores)
                
        except Exception as e:
            self.logger.error(f"Failed to save learning data: {e}")
    
    def reset(self, module: Optional[str] = None) -> None:
        """
        Reset learning data.
        
        Args:
            module: Specific module to reset (None for all)
        """
        with self._lock:
            if module:
                
                if module in self._weights:
                    self._weights[module] = {}
                self._module_scores[module] = 0.5
                self._threshold_adjustments[module] = 0.0
            else:
               
                self._weights = {}
                self._module_scores = {m: 0.5 for m in DetectionModules.all()}
                self._threshold_adjustments = {}
            
           
            self._save_learning_data()
