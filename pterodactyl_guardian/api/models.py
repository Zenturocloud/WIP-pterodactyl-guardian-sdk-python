"""
Data models for the Pterodactyl API.

This module provides data models for various resources returned by the
Pterodactyl API, providing a clean interface for accessing properties.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime


@dataclass
class User:
    """Representation of a Pterodactyl Panel user."""
    
    id: Union[str, int]
    username: str
    email: str
    first_name: str
    last_name: str
    language: str
    admin: bool
    suspended: bool
    root_admin: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    notes: Optional[str] = None
    external_id: Optional[str] = None
    uuid: Optional[str] = None
    
    @classmethod
    def from_api_data(cls, data: Dict[str, Any]) -> 'User':
        """
        Create a User object from API data.
        
        Args:
            data: API response data
            
        Returns:
            User object
        """
        
        if "attributes" in data:
            attrs = data["attributes"]
        else:
            attrs = data
        
       
        created_at = datetime.fromisoformat(attrs['created_at'].replace('Z', '+00:00')) if attrs.get('created_at') else None
        updated_at = datetime.fromisoformat(attrs['updated_at'].replace('Z', '+00:00')) if attrs.get('updated_at') else None
        
        return cls(
            id=attrs.get('id'),
            username=attrs.get('username', ''),
            email=attrs.get('email', ''),
            first_name=attrs.get('first_name', ''),
            last_name=attrs.get('last_name', ''),
            language=attrs.get('language', 'en'),
            admin=attrs.get('admin', False),
            suspended=attrs.get('suspended', False),
            root_admin=attrs.get('root_admin', False),
            created_at=created_at,
            updated_at=updated_at,
            notes=attrs.get('notes'),
            external_id=attrs.get('external_id'),
            uuid=attrs.get('uuid')
        )
    
    @property
    def full_name(self) -> str:
        """Get the user's full name."""
        return f"{self.first_name} {self.last_name}".strip()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'language': self.language,
            'admin': self.admin,
            'suspended': self.suspended,
            'root_admin': self.root_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'notes': self.notes,
            'external_id': self.external_id,
            'uuid': self.uuid
        }


@dataclass
class Allocation:
    """Representation of a Pterodactyl Panel server allocation."""
    
    id: Union[str, int]
    ip: str
    port: int
    alias: Optional[str] = None
    assigned: bool = False
    
    @classmethod
    def from_api_data(cls, data: Dict[str, Any]) -> 'Allocation':
        """
        Create an Allocation object from API data.
        
        Args:
            data: API response data
            
        Returns:
            Allocation object
        """
        
        if "attributes" in data:
            attrs = data["attributes"]
        else:
            attrs = data
        
        return cls(
            id=attrs.get('id'),
            ip=attrs.get('ip', ''),
            port=attrs.get('port', 0),
            alias=attrs.get('alias'),
            assigned=attrs.get('assigned', False)
        )


@dataclass
class Server:
    """Representation of a Pterodactyl Panel server."""
    
    id: Union[str, int]
    identifier: str
    name: str
    description: Optional[str]
    status: str
    suspended: bool
    limits: Dict[str, Any]
    feature_limits: Dict[str, Any]
    user_id: Union[str, int]
    node_id: Union[str, int]
    allocations: List[Allocation] = field(default_factory=list)
    user: Optional[User] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @classmethod
    def from_api_data(cls, data: Dict[str, Any]) -> 'Server':
        """
        Create a Server object from API data.
        
        Args:
            data: API response data
            
        Returns:
            Server object
        """
       
        if "attributes" in data:
            attrs = data["attributes"]
        else:
            attrs = data
        
        
        created_at = datetime.fromisoformat(attrs['created_at'].replace('Z', '+00:00')) if attrs.get('created_at') else None
        updated_at = datetime.fromisoformat(attrs['updated_at'].replace('Z', '+00:00')) if attrs.get('updated_at') else None
        
        
        allocations = []
        if 'relationships' in data and 'allocations' in data['relationships']:
            alloc_data = data['relationships']['allocations']['data']
            allocations = [Allocation.from_api_data(a) for a in alloc_data]
        elif 'allocations' in attrs:
            allocations = [Allocation.from_api_data(a) for a in attrs['allocations']]
        
        
        user = None
        if 'relationships' in data and 'user' in data['relationships']:
            user_data = data['relationships']['user']['data']
            user = User.from_api_data(user_data)
        elif 'user' in attrs:
            user = User.from_api_data(attrs['user'])
        
        return cls(
            id=attrs.get('id'),
            identifier=attrs.get('identifier', ''),
            name=attrs.get('name', ''),
            description=attrs.get('description'),
            status=attrs.get('status', 'unknown'),
            suspended=attrs.get('suspended', False),
            limits=attrs.get('limits', {}),
            feature_limits=attrs.get('feature_limits', {}),
            user_id=attrs.get('user', 0),
            node_id=attrs.get('node', 0),
            allocations=allocations,
            user=user,
            created_at=created_at,
            updated_at=updated_at
        )
    
    @property
    def primary_allocation(self) -> Optional[Allocation]:
        """Get the server's primary allocation."""
        for allocation in self.allocations:
            if allocation.assigned:
                return allocation
        return None if not self.allocations else self.allocations[0]
    
    @property
    def address(self) -> str:
        """Get the server's address (IP:Port)."""
        alloc = self.primary_allocation
        if alloc:
            return f"{alloc.ip}:{alloc.port}"
        return "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'identifier': self.identifier,
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'suspended': self.suspended,
            'limits': self.limits,
            'feature_limits': self.feature_limits,
            'user_id': self.user_id,
            'node_id': self.node_id,
            'allocations': [a.__dict__ for a in self.allocations],
            'user': self.user.to_dict() if self.user else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


@dataclass
class File:
    """Representation of a file on a Pterodactyl Panel server."""
    
    name: str
    mode: str
    size: int
    is_file: bool
    is_symlink: bool
    is_editable: bool
    mimetype: str
    created_at: datetime
    modified_at: datetime
    
    @classmethod
    def from_api_data(cls, data: Dict[str, Any]) -> 'File':
        """
        Create a File object from API data.
        
        Args:
            data: API response data
            
        Returns:
            File object
        """
        
        if "attributes" in data:
            attrs = data["attributes"]
        else:
            attrs = data
        
        
        created_at = datetime.fromisoformat(attrs['created_at'].replace('Z', '+00:00')) if attrs.get('created_at') else datetime.now()
        modified_at = datetime.fromisoformat(attrs['modified_at'].replace('Z', '+00:00')) if attrs.get('modified_at') else datetime.now()
        
        return cls(
            name=attrs.get('name', ''),
            mode=attrs.get('mode', ''),
            size=attrs.get('size', 0),
            is_file=attrs.get('is_file', True),
            is_symlink=attrs.get('is_symlink', False),
            is_editable=attrs.get('is_editable', False),
            mimetype=attrs.get('mimetype', 'application/octet-stream'),
            created_at=created_at,
            modified_at=modified_at
        )


@dataclass
class Resource:
    """Representation of server resource usage."""
    
    cpu: float = 0.0
    memory: float = 0.0
    disk: float = 0.0
    network: Dict[str, float] = field(default_factory=lambda: {"rx_bytes": 0, "tx_bytes": 0})
    uptime: float = 0.0
    state: str = "offline"
    
    @classmethod
    def from_api_data(cls, data: Dict[str, Any]) -> 'Resource':
        """
        Create a Resource object from API data.
        
        Args:
            data: API response data
            
        Returns:
            Resource object
        """
        if not data:
            return cls()
        
        return cls(
            cpu=data.get('cpu_absolute', 0.0),
            memory=data.get('memory_bytes', 0.0),
            disk=data.get('disk_bytes', 0.0),
            network={
                "rx_bytes": data.get('network_rx_bytes', 0),
                "tx_bytes": data.get('network_tx_bytes', 0)
            },
            uptime=data.get('uptime', 0.0),
            state=data.get('state', 'offline')
        )
