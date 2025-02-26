"""
Utility functions for Pterodactyl Guardian SDK.

This module provides various utility functions used throughout the SDK,
including ID generation, content hashing, and file fingerprinting.
"""

import os
import re
import uuid
import hashlib
from typing import Dict, List, Any, Optional, Union, Set, Tuple
import random
import string


def generate_id() -> str:
    """
    Generate a unique identifier.
    
    Returns:
        Unique identifier string
    """
    return str(uuid.uuid4())


def hash_content(content: str) -> str:
    """
    Generate a hash of content.
    
    Args:
        content: Content to hash
        
    Returns:
        SHA-256 hash of content
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def create_file_fingerprint(content: str) -> str:
    """
    Create a fingerprint for a file based on its content.
    
    This implements a fuzzy hashing approach that is resistant to minor changes
    while still detecting significantly similar files.
    
    Args:
        content: File content
        
    Returns:
        File fingerprint
    """
    
    normalized = _normalize_content(content)
    
    
    chunks = _create_chunks(normalized)
    
    
    chunk_hashes = [hashlib.md5(chunk.encode("utf-8")).hexdigest()[:8] for chunk in chunks]
    
    
    return "-".join(chunk_hashes)


def _normalize_content(content: str) -> str:
    """
    Normalize content by removing comments and whitespace.
    
    Args:
        content: Content to normalize
        
    Returns:
        Normalized content
    """
   
    content = re.sub(r"(?://.*)|(?:/\*[\s\S]*?\*/)", "", content)
    
   
    content = re.sub(r"\s+", " ", content)
    
    return content.strip()


def _create_chunks(content: str, chunk_size: int = 64) -> List[str]:
    """
    Create chunks of content for fingerprinting.
    
    Args:
        content: Content to chunk
        chunk_size: Size of each chunk
        
    Returns:
        List of content chunks
    """
    chunks = []
    
    
    content_length = len(content)
    
    if content_length <= chunk_size:
        chunks.append(content)
    else:
        
        num_chunks = min(8, content_length // chunk_size)
        
        
        actual_chunk_size = content_length // num_chunks
        
        
        for i in range(num_chunks):
            start = i * actual_chunk_size
            end = start + actual_chunk_size if i < num_chunks - 1 else content_length
            chunks.append(content[start:end])
    
    return chunks


def sanitize_path(path: str) -> str:
    """
    Sanitize a path to prevent directory traversal attacks.
    
    Args:
        path: Path to sanitize
        
    Returns:
        Sanitized path
    """
    
    path = os.path.normpath(path)
    
    
    if ":" in path:
        path = path.split(":", 1)[1]
    
    
    if path.startswith("/"):
        path = path[1:]
    
    
    path = path.replace("..", "")
    
    return path


def extract_extension(path: str) -> str:
    """
    Extract the file extension from a path.
    
    Args:
        path: File path
        
    Returns:
        File extension (without dot)
    """
    _, ext = os.path.splitext(path)
    return ext[1:] if ext.startswith(".") else ext


def get_file_type(path: str) -> str:
    """
    Get the file type based on the file extension.
    
    Args:
        path: File path
        
    Returns:
        File type (php, js, py, etc.)
    """
    extension = extract_extension(path).lower()
    
    
    extension_map = {
        "php": "php",
        "js": "javascript",
        "py": "python",
        "rb": "ruby",
        "pl": "perl",
        "sh": "shell",
        "bash": "shell",
        "html": "html",
        "htm": "html",
        "css": "css",
        "json": "json",
        "xml": "xml",
        "yml": "yaml",
        "yaml": "yaml",
        "md": "markdown",
        "txt": "text",
        "log": "text",
        "conf": "config",
        "cfg": "config",
        "ini": "config",
        "sql": "sql",
        "java": "java",
        "class": "java",
        "jar": "java",
        "c": "c",
        "cpp": "cpp",
        "h": "c",
        "hpp": "cpp",
        "cs": "csharp",
        "go": "go",
        "rs": "rust",
        "ts": "typescript",
        "jsx": "react",
        "tsx": "react",
    }
    
    return extension_map.get(extension, "unknown")


def calculate_similarity(content1: str, content2: str) -> float:
    """
    Calculate the similarity between two content strings.
    
    Uses a combination of fuzzy hashing and Jaccard similarity to calculate
    a score between 0.0 and 1.0, where 1.0 is an exact match.
    
    Args:
        content1: First content string
        content2: Second content string
        
    Returns:
        Similarity score between 0.0 and 1.0
    """
    
    norm1 = _normalize_content(content1)
    norm2 = _normalize_content(content2)
    
    
    if norm1 == norm2:
        return 1.0
    
   
    fp1 = create_file_fingerprint(content1)
    fp2 = create_file_fingerprint(content2)
    
    
    chunks1 = fp1.split("-")
    chunks2 = fp2.split("-")
    
   
    set1 = set(chunks1)
    set2 = set(chunks2)
    
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    return intersection / union if union > 0 else 0.0


def tokenize_content(content: str) -> List[str]:
    """
    Tokenize content into words and symbols.
    
    Args:
        content: Content to tokenize
        
    Returns:
        List of tokens
    """
    
    content = re.sub(r"\s+", " ", content)
    
   
    tokens = re.findall(r"[a-zA-Z0-9_]+|[^\w\s]", content)
    
    return tokens


def generate_temp_filename() -> str:
    """
    Generate a temporary filename.
    
    Returns:
        Temporary filename
    """
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"temp_{random_part}"


def is_binary_content(content: bytes, sample_size: int = 1024) -> bool:
    """
    Check if content is binary or text.
    
    Args:
        content: Content to check
        sample_size: Number of bytes to check
        
    Returns:
        True if content is binary, False if it's text
    """
    if not content:
        return False
    
    
    sample = content[:sample_size]
    
    
    null_count = sample.count(b'\x00')
    control_count = sum(1 for b in sample if b < 9 or (b > 13 and b < 32))
    
    
    total_size = len(sample)
    suspicious_ratio = (null_count + control_count) / total_size
    
   
    return suspicious_ratio > 0.1


def shorten_content(content: str, max_length: int = 100) -> str:
    """
    Shorten content for display purposes.
    
    Args:
        content: Content to shorten
        max_length: Maximum length
        
    Returns:
        Shortened content
    """
    if len(content) <= max_length:
        return content
    
    half = max_length // 2 - 2
    return f"{content[:half]}...{content[-half:]}"
