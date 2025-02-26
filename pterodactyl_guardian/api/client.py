"""
Client API wrapper for Pterodactyl Panel.

This module provides a client for interacting with the Pterodactyl Panel
Client API, which uses a client/user-level API key.
"""

import logging
import time
import requests
from typing import Dict, List, Optional, Any, Union, BinaryIO
from urllib.parse import urljoin

from ..exceptions import (
    APIError, 
    AuthenticationError, 
    ResourceNotFoundError, 
    RateLimitError,
    ConnectionError
)
from .models import Server, File, Resource


class ClientAPI:
    """
    Client for the Pterodactyl Panel Client API (user level).
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
        Initialize the Client API wrapper.
        
        Args:
            panel_url: URL to the Pterodactyl Panel
            api_key: Pterodactyl Client API key
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
        
        self.base_url = f"{self.panel_url}/api/client"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        self.session = requests.Session()
        
        
        self._cache = {
            "servers": {},
            "last_updated": {}
        }
    
    def _request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, BinaryIO]] = None
    ) -> Dict[str, Any]:
        """
        Make a request to the API with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            params: Query parameters
            data: Form data
            json_data: JSON data
            files: Files to upload
            
        Returns:
            Parsed JSON response
        
        Raises:
            APIError: For API-related errors
            ConnectionError: For network-related errors
        """
        url = urljoin(self.base_url, endpoint.lstrip("/"))
        
        
        headers = self.headers.copy()
        if files:
            headers.pop("Content-Type", None)
        
        for attempt in range(self.max_retries):
            try:
                self.logger.debug(f"{method} {url}")
                
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_data,
                    files=files,
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
            # Check if response is empty or not JSON
            if not response.content:
                return {}
            return response.json()
        except requests.exceptions.JSONDecodeError:
            if response.status_code == 204:  # No Content
                return {}
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
            
            # Try to get detailed error message from response
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
    
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a GET request to the API."""
        return self._request("GET", endpoint, params=params)
    
    def post(self, endpoint: str, json_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make a POST request to the API."""
        return self._request("POST", endpoint, json_data=json_data)
    
    def put(self, endpoint: str, json_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make a PUT request to the API."""
        return self._request("PUT", endpoint, json_data=json_data)
    
    def patch(self, endpoint: str, json_data: Dict[str, Any] = None) -> Dict[str, Any]:
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
            response = self.get("account")
            return "attributes" in response
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def get_account(self) -> Dict[str, Any]:
        """
        Get the account information for the authenticated user.
        
        Returns:
            Account information
        """
        response = self.get("account")
        return response.get("attributes", {})
    
    def get_servers(self) -> List[Server]:
        """
        Get a list of all servers accessible to the authenticated user.
        
        Returns:
            List of Server objects
        """
        response = self.get("servers")
        data = response.get("data", [])
        return [Server.from_api_data(server_data) for server_data in data]
    
    def get_server_resources(self, server_id: str) -> Resource:
        """
        Get resource usage for a specific server.
        
        Args:
            server_id: ID of the server
            
        Returns:
            Resource object
        """
        response = self.get(f"servers/{server_id}/resources")
        return Resource.from_api_data(response.get("attributes", {}))
    
    def get_server_files(self, server_id: str, directory: str = "/") -> List[File]:
        """
        Get a list of files in a directory for a specific server.
        
        Args:
            server_id: ID of the server
            directory: Directory path
            
        Returns:
            List of File objects
        """
        params = {"directory": directory}
        response = self.get(f"servers/{server_id}/files/list", params=params)
        data = response.get("data", [])
        return [File.from_api_data(file_data) for file_data in data]
    
    def get_file_contents(self, server_id: str, file_path: str) -> str:
        """
        Get the contents of a file for a specific server.
        
        Args:
            server_id: ID of the server
            file_path: Path to the file
            
        Returns:
            File contents
        """
        params = {"file": file_path}
        url = f"{self.base_url}/servers/{server_id}/files/contents"
        
        for attempt in range(self.max_retries):
            try:
                self.logger.debug(f"GET {url}")
                
                response = self.session.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=self.timeout
                )
                
                response.raise_for_status()
                return response.text
            
            except requests.exceptions.HTTPError as e:
                if response.status_code == 404:
                    raise ResourceNotFoundError(
                        f"File not found: {file_path}",
                        status_code=404,
                        response=response,
                        endpoint=f"servers/{server_id}/files/contents"
                    )
                elif response.status_code == 429 and attempt < self.max_retries - 1:
                    delay = self.retry_delay * (attempt + 1)
                    self.logger.warning(f"Rate limited. Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    raise APIError(
                        f"API error: {response.status_code}",
                        status_code=response.status_code,
                        response=response,
                        endpoint=f"servers/{server_id}/files/contents"
                    )
            except requests.exceptions.RequestException as e:
                raise ConnectionError(
                    f"Error connecting to API: {e}",
                    endpoint=f"servers/{server_id}/files/contents"
                )
        
        raise RateLimitError(
            "Maximum retry attempts exceeded",
            endpoint=f"servers/{server_id}/files/contents"
        )
    
    def write_file(self, server_id: str, file_path: str, content: str) -> bool:
        """
        Write content to a file on a specific server.
        
        Args:
            server_id: ID of the server
            file_path: Path to the file
            content: Content to write
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.post(
                f"servers/{server_id}/files/write",
                {
                    "file": file_path,
                    "content": content
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Error writing file {file_path}: {e}")
            return False
    
    def rename_file(self, server_id: str, file_path: str, new_name: str) -> bool:
        """
        Rename a file or directory on a specific server.
        
        Args:
            server_id: ID of the server
            file_path: Path to the file or directory
            new_name: New name for the file or directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            
            path_parts = file_path.rsplit("/", 1)
            directory = path_parts[0] if len(path_parts) > 1 else "/"
            from_file = path_parts[-1]
            
            
            if "/" in new_name:
                to_file = new_name
            else:
                
                to_file = f"{directory}/{new_name}" if directory != "/" else f"/{new_name}"
            
            self.put(
                f"servers/{server_id}/files/rename",
                {
                    "root": directory,
                    "files": [
                        {
                            "from": from_file,
                            "to": to_file
                        }
                    ]
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Error renaming file {file_path}: {e}")
            return False
    
    def delete_file(self, server_id: str, file_path: str) -> bool:
        """
        Delete a file or directory on a specific server.
        
        Args:
            server_id: ID of the server
            file_path: Path to the file or directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            
            path_parts = file_path.rsplit("/", 1)
            directory = path_parts[0] if len(path_parts) > 1 else "/"
            files = [path_parts[-1]]
            
            self.post(
                f"servers/{server_id}/files/delete",
                {
                    "root": directory,
                    "files": files
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Error deleting file {file_path}: {e}")
            return False
    
    def create_directory(self, server_id: str, path: str, name: str) -> bool:
        """
        Create a directory on a specific server.
        
        Args:
            server_id: ID of the server
            path: Path where to create the directory
            name: Name of the directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.post(
                f"servers/{server_id}/files/create-folder",
                {
                    "root": path,
                    "name": name
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Error creating directory {path}/{name}: {e}")
            return False
    
    def compress_files(self, server_id: str, root: str, files: List[str], file_name: str) -> bool:
        """
        Compress files into an archive on a specific server.
        
        Args:
            server_id: ID of the server
            root: Root directory
            files: List of files to compress
            file_name: Name of the archive
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.post(
                f"servers/{server_id}/files/compress",
                {
                    "root": root,
                    "files": files,
                    "file_name": file_name
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Error compressing files in {root}: {e}")
            return False
    
    def decompress_file(self, server_id: str, root: str, file: str) -> bool:
        """
        Decompress an archive on a specific server.
        
        Args:
            server_id: ID of the server
            root: Root directory
            file: Archive file to decompress
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.post(
                f"servers/{server_id}/files/decompress",
                {
                    "root": root,
                    "file": file
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Error decompressing {file} in {root}: {e}")
            return False
