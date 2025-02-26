"""
Event signaling system for Pterodactyl Guardian SDK.

This module provides an event signaling system that allows components to emit
and receive signals, enabling loose coupling between components.
"""

import inspect
import logging
import threading
import queue
import time
from typing import Dict, List, Any, Callable, Optional, Set, Tuple, Type


class Signal:
    """Base signal class that components can subscribe to and emit."""
    
    def __init__(self, name: str, description: str = "", async_delivery: bool = False):
        """
        Initialize a signal.
        
        Args:
            name: Signal name
            description: Signal description
            async_delivery: Whether to deliver signals asynchronously
        """
        self.name = name
        self.description = description
        self.async_delivery = async_delivery
        self.receivers: List[Tuple[Callable, Dict[str, Any]]] = []
        self.lock = threading.RLock()
        
        
        self.queue = queue.Queue() if async_delivery else None
        self.delivery_thread = None
        self.running = False
    
    def connect(self, receiver: Callable, **kwargs) -> None:
        """
        Connect a receiver to this signal.
        
        Args:
            receiver: Callable to receive the signal
            **kwargs: Additional arguments to pass to the receiver
        """
        with self.lock:
            self.receivers.append((receiver, kwargs))
            
            # Start delivery thread if async
            if self.async_delivery and not self.running:
                self._start_delivery_thread()
    
    def disconnect(self, receiver: Callable) -> None:
        """
        Disconnect a receiver from this signal.
        
        Args:
            receiver: Callable to disconnect
        """
        with self.lock:
            self.receivers = [(r, kw) for r, kw in self.receivers if r != receiver]
    
    def send(self, sender: Any, **kwargs) -> List[Any]:
        """
        Send a signal.
        
        Args:
            sender: Signal sender
            **kwargs: Signal data
            
        Returns:
            List of return values from receivers
        """
        if self.async_delivery:
            if not self.running:
                self._start_delivery_thread()
            self.queue.put((sender, kwargs))
            return []
        else:
            return self._deliver(sender, kwargs)
    
    def _deliver(self, sender: Any, kwargs: Dict[str, Any]) -> List[Any]:
        """
        Deliver a signal to all receivers.
        
        Args:
            sender: Signal sender
            kwargs: Signal data
            
        Returns:
            List of return values from receivers
        """
        responses = []
        
        with self.lock:
            
            receivers = list(self.receivers)
        
        for receiver, receiver_kwargs in receivers:
            try:
                
                combined_kwargs = receiver_kwargs.copy()
                combined_kwargs.update(kwargs)
                
                
                if 'sender' in inspect.signature(receiver).parameters:
                    responses.append(receiver(sender=sender, **combined_kwargs))
                else:
                    responses.append(receiver(**combined_kwargs))
            except Exception as e:
                
                logging.getLogger(__name__).error(
                    f"Error delivering signal {self.name} to {receiver}: {e}"
                )
        
        return responses
    
    def _start_delivery_thread(self) -> None:
        """Start the async delivery thread."""
        self.running = True
        self.delivery_thread = threading.Thread(target=self._delivery_loop)
        self.delivery_thread.daemon = True
        self.delivery_thread.start()
    
    def _delivery_loop(self) -> None:
        """Async delivery loop."""
        while self.running:
            try:
                
                try:
                    sender, kwargs = self.queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                
               
                self._deliver(sender, kwargs)
                
                
                self.queue.task_done()
            except Exception as e:
                
                logging.getLogger(__name__).error(
                    f"Error in delivery loop for signal {self.name}: {e}"
                )
    
    def stop(self) -> None:
        """Stop the async delivery thread."""
        if self.async_delivery and self.running:
            self.running = False
            if self.delivery_thread:
                self.delivery_thread.join(timeout=1.0)
                self.delivery_thread = None


class SignalManager:
    """Manager for creating and accessing signals."""
    
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls):
        """Singleton pattern to ensure only one instance of SignalManager."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SignalManager, cls).__new__(cls)
                cls._instance._signals = {}
                cls._instance._logger = logging.getLogger(__name__)
        
        return cls._instance
    
    def get_or_create(self, name: str, description: str = "", async_delivery: bool = False) -> Signal:
        """
        Get or create a signal.
        
        Args:
            name: Signal name
            description: Signal description
            async_delivery: Whether to deliver signals asynchronously
            
        Returns:
            Signal instance
        """
        with self._lock:
            if name not in self._signals:
                self._signals[name] = Signal(name, description, async_delivery)
            return self._signals[name]
    
    def get(self, name: str) -> Optional[Signal]:
        """
        Get a signal by name.
        
        Args:
            name: Signal name
            
        Returns:
            Signal instance or None if not found
        """
        return self._signals.get(name)
    
    def list_signals(self) -> List[Dict[str, Any]]:
        """
        List all registered signals.
        
        Returns:
            List of signal information
        """
        with self._lock:
            return [
                {
                    "name": signal.name,
                    "description": signal.description,
                    "async": signal.async_delivery,
                    "receivers": len(signal.receivers)
                }
                for signal in self._signals.values()
            ]
    
    def clear(self) -> None:
        """Clear all signals."""
        with self._lock:
            for signal in self._signals.values():
                signal.stop()
            self._signals.clear()



class CommonSignals:
    """Common signals used throughout the SDK."""
    
    DETECTION_FOUND = "detection.found"
    DETECTION_REVIEWED = "detection.reviewed"
    USER_ADDED = "user.added"
    USER_UPDATED = "user.updated"
    FILE_ADDED = "file.added"
    FILE_UPDATED = "file.updated"
    FILE_QUARANTINED = "file.quarantined"
    SERVER_ADDED = "server.added"
    SERVER_UPDATED = "server.updated"
    RESOURCE_ALERT = "resource.alert"
    CONFIG_UPDATED = "config.updated"
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    PATTERN_ADDED = "pattern.added"
    PATTERN_UPDATED = "pattern.updated"
    LEARNING_FEEDBACK = "learning.feedback"



signal_manager = SignalManager()


def get_signal(name: str, description: str = "", async_delivery: bool = False) -> Signal:
    """
    Get or create a signal.
    
    Args:
        name: Signal name
        description: Signal description
        async_delivery: Whether to deliver signals asynchronously
        
    Returns:
        Signal instance
    """
    return signal_manager.get_or_create(name, description, async_delivery)
