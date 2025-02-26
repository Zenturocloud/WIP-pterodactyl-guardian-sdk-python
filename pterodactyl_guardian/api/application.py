"""
Application API client for Pterodactyl Panel.

This module provides a client for interacting with the Pterodactyl Panel
Application API, which requires an admin-level API key.
"""

import logging
import time
import requests
from typing import Dict, List, Optional, Any, Union, Tuple
from urllib.parse import urljoin

from ..exceptions import (
    APIError, 
    AuthenticationError, 
    ResourceNotFoundError, 
    RateLimitError,
    ConnectionError
)
from .models import User, Server, File, Resource


class ApplicationAPI:
    """
    Client for the Pterodactyl Panel Application API (admin level).
    """
    
    def __init__(
        self,
        panel_url: str,
        api_key: str,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: int = 2,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the Application API client.
        
        Args:
            panel_url: URL to the Pterodactyl Panel
            api_key: Pterodactyl Application API key
            timeout: API request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            retry_delay: Delay between retries in seconds
            logger: Logger instance
        """
        self.panel_url = panel_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.logger = logger or logging.getLogger(__name__)
        
        self.base_url = f"{self.panel_url}/api/application"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        self.session = requests.Session()
        
        
        self._cache = {
            "users": {},
            "servers": {},
            "nodes": {},
            "locations": {},
            "last_updated": {}
        }
    
    def _request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make a request to the API with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            params: Query parameters
            data: Form data
            json_data: JSON data
            
        Returns:
            Parsed JSON response
        
        Raises:
            APIError: For API-related errors
            ConnectionError: For network-related errors
        """
        url = urljoin(self.base_url, endpoint.lstrip("/"))
        
        for attempt in range(self.max_retries):
            try:
                self.logger.debug(f"{method} {url}")
                
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=self.timeout
                )
                
                return self._handle_response(response, endpoint)
            
            except (RateLimitError, ConnectionError) as e:
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (attempt + 1)
                    self.logger.warning(f"Request failed: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
                else:
                    raise
            except Exception as e:
                if not isinstance(e, APIError):
                    self.logger.error(f"Unexpected error: {e}")
                    raise ConnectionError(f"Error connecting to API: {e}")
                raise
    
    def _handle_response(self, response: requests.Response, endpoint: str) -> Dict[str, Any]:
        """
        Handle the API response and raise appropriate exceptions.
        
        Args:
            response: Response from the API
            endpoint: API endpoint for context
            
        Returns:
            Parsed JSON response
            
        Raises:
            AuthenticationError: For authentication failures
            ResourceNotFoundError: When a resource is not found
            RateLimitError: When rate limited
            APIError: For other API errors
        """
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.JSONDecodeError:
            raise APIError(f"Invalid JSON response from API: {endpoint}", response=response)
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                raise AuthenticationError(
                    "Authentication failed: Invalid API key", 
                    status_code=401, 
                    response=response,
                    endpoint=endpoint
                )
            elif response.status_code == 403:
                raise AuthenticationError(
                    "Authentication failed: Insufficient permissions",
                    status_code=403,
                    response=response,
                    endpoint=endpoint
                )
            elif response.status_code == 404:
                raise ResourceNotFoundError(
                    f"Resource not found: {endpoint}",
                    status_code=404,
                    response=response,
                    endpoint=endpoint
                )
            elif response.status_code == 429:
                raise RateLimitError(
                    "API rate limit exceeded",
                    status_code=429,
                    response=response,
                    endpoint=endpoint
                )
            
            
            error_message = f"API error: {response.status_code}"
            try:
                error_data = response.json()
                if "errors" in error_data and error_data["errors"]:
                    if isinstance(error_data["errors"], list):
                        error_message = f"{error_message} - {error_data['errors'][0].get('detail', '')}"
                    elif isinstance(error_data["errors"], dict):
                        error_message = f"{error_message} - {next(iter(error_data['errors'].values()), [''])[0]}"
            except (ValueError, KeyError, IndexError):
                pass
            
            raise APIError(
                error_message,
                status_code=response.status_code,
                response=response,
                endpoint=endpoint
            )
        except requests.exceptions.RequestException as e:
            raise ConnectionError(
                f"Error connecting to API: {e}",
                endpoint=endpoint
            )
    
    def _get_paginated(
        self, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        max_pages: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all pages of a paginated endpoint.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            max_pages: Maximum number of pages to fetch (None for all)
            
        Returns:
            List of data items from all pages
        """
        params = params or {}
        items = []
        page = 1
        
        while True:
            params["page"] = page
            response = self._request("GET", endpoint, params=params)
            
            if "data" not in response:
                break
            
            items.extend(response["data"])
            
            
            if "meta" in response and "pagination" in response["meta"]:
                pagination = response["meta"]["pagination"]
                if page >= pagination.get("total_pages", 1) or (max_pages and page >= max_pages):
                    break
                page += 1
            else:
                break
        
        return items
    
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a GET request to the API."""
        return self._request("GET", endpoint, params=params)
    
    def post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a POST request to the API."""
        return self._request("POST", endpoint, json_data=json_data)
    
    def patch(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a PATCH request to the API."""
        return self._request("PATCH", endpoint, json_data=json_data)
    
    def delete(self, endpoint: str) -> Dict[str, Any]:
        """Make a DELETE request to the API."""
        return self._request("DELETE", endpoint)
    
    def test_connection(self) -> bool:
        """
        Test the connection to the API.
        
        Returns:
            True if the connection is successful, False otherwise
        """
        try:
            response = self.get("nodes")
            return "data" in response
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def get_users(self, include_suspended: bool = False) -> List[User]:
        """
        Get a list of all users.
        
        Args:
            include_suspended: Whether to include suspended users
            
        Returns:
            List of User objects
        """
        params = {}
        if not include_suspended:
            params["filter[suspended]"] = "0"
        
        data = self._get_paginated("users", params=params)
        return [User.from_api_data(user_data) for user_data in data]
    
    def get_user(self, user_id: Union[str, int]) -> User:
        """
        Get details for a specific user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            User object
        """
        response = self.get(f"users/{user_id}")
        return User.from_api_data(response["attributes"])
    
    def get_servers(self, include_suspended: bool = False) -> List[Server]:
        """
        Get a list of all servers.
        
        Args:
            include_suspended: Whether to include suspended servers
            
        Returns:
            List of Server objects
        """
        params = {"include": "allocations,user"}
        if not include_suspended:
            params["filter[suspended]"] = "0"
        
        data = self._get_paginated("servers", params=params)
        return [Server.from_api_data(server_data) for server_data in data]
    
    def get_server(self, server_id: Union[str, int]) -> Server:
        """
        Get details for a specific server.
        
        Args:
            server_id: ID of the server
            
        Returns:
            Server object
        """
        response = self.get(f"servers/{server_id}?include=allocations,user")
        return Server.from_api_data(response["attributes"])
    
    def get_user_servers(self, user_id: Union[str, int]) -> List[Server]:
        """
        Get a list of servers owned by a specific user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            List of Server objects
        """
        params = {"filter[user_id]": user_id, "include": "allocations"}
        data = self._get_paginated("servers", params=params)
        return [Server.from_api_data(server_data) for server_data in data]
    
    def add_user_note(self, user_id: Union[str, int], note: str) -> bool:
        """
        Add a note to a user account.
        
        Args:
            user_id: ID of the user
            note: Note to add
            
        Returns:
            True if successful, False otherwise
        """
        try:
            user = self.get_user(user_id)
            existing_notes = user.notes or ""
            
            if existing_notes:
                updated_notes = f"{existing_notes}\n\n{note}"
            else:
                updated_notes = note
            
            self.patch(f"users/{user_id}", {"notes": updated_notes})
            return True
        except Exception as e:
            self.logger.error(f"Error adding note to user {user_id}: {e}")
            return False
    
    def suspend_user(self, user_id: Union[str, int]) -> bool:
        """
        Suspend a user account.
        
        Args:
            user_id: ID of the user
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.patch(f"users/{user_id}/suspend", {})
            return True
        except Exception as e:
            self.logger.error(f"Error suspending user {user_id}: {e}")
            return False
    
    def unsuspend_user(self, user_id: Union[str, int]) -> bool:
        """
        Unsuspend a user account.
        
        Args:
            user_id: ID of the user
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.patch(f"users/{user_id}/unsuspend", {})
            return True
        except Exception as e:
            self.logger.error(f"Error unsuspending user {user_id}: {e}")
            return False
