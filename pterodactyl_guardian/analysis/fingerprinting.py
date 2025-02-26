"""
Code fingerprinting for the Pterodactyl Guardian SDK.

This module provides functionality to generate unique fingerprints
for code snippets that can be used for identification and comparison.
"""

import hashlib
import re
from typing import Dict, List, Any, Optional, Union, Set, Tuple, Callable
import logging
from collections import Counter

from ..core.utils import tokenize_content
from ..exceptions import AnalysisError


class FingerprintGenerator:
    """
    Generator for code fingerprints.
    
    This class creates different types of fingerprints for code snippets,
    allowing for both exact and fuzzy matching.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the fingerprint generator.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
    
    def generate(
        self,
        content: str,
        method: str = "combined",
        normalize: bool = True
    ) -> Dict[str, Any]:
        """
        Generate fingerprints for code content.
        
        Args:
            content: Code content
            method: Fingerprinting method
            normalize: Whether to normalize the code
            
        Returns:
            Dictionary of fingerprints
            
        Raises:
            AnalysisError: If fingerprint generation fails
        """
        if not content:
            return {
                "hash": "",
                "method": method,
                "normalized": False,
                "token_hash": "",
                "structural_hash": "",
                "ngram_hash": "",
                "semantic_hash": ""
            }
        
        try:
           
            normalized_content = self._normalize_code(content) if normalize else content
            
     
            result = {
                "method": method,
                "normalized": normalize,
                "hash": hashlib.sha256(content.encode()).hexdigest()
            }
            
            if method in ["combined", "token"]:
                result["token_hash"] = self._generate_token_fingerprint(normalized_content)
            
            if method in ["combined", "structural"]:
                result["structural_hash"] = self._generate_structural_fingerprint(normalized_content)
            
            if method in ["combined", "ngram"]:
                result["ngram_hash"] = self._generate_ngram_fingerprint(normalized_content)
            
            if method in ["combined", "semantic"]:
                result["semantic_hash"] = self._generate_semantic_fingerprint(normalized_content)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error generating fingerprint: {e}")
            raise AnalysisError(f"Failed to generate fingerprint: {e}")
    
    def _normalize_code(self, content: str) -> str:
        """
        Normalize code for fingerprinting.
        
        Args:
            content: Code content
            
        Returns:
            Normalized code
        """
      
        content = re.sub(r"(?://.*)|(?:/\*[\s\S]*?\*/)|(?:#.*)", "", content)
        
      
        content = re.sub(r"\s+", " ", content)
        
      
        content = re.sub(r'"([^"\\]|\\.)*"', '"STR"', content)
        content = re.sub(r"'([^'\\]|\\.)*'", "'STR'", content)
        
     
        content = re.sub(r"\b\d+\b", "NUM", content)
        
        return content.strip()
    
    def _generate_token_fingerprint(self, content: str) -> str:
        """
        Generate a fingerprint based on token frequency.
        
        Args:
            content: Normalized code content
            
        Returns:
            Token-based fingerprint
        """
        
        tokens = tokenize_content(content)
        

        counter = Counter(tokens)
        
      
        token_counts = sorted(
            [(token, count) for token, count in counter.items()],
            key=lambda x: (x[1], x[0]),
            reverse=True
        )
        
        
        top_tokens = token_counts[:50]
        

        token_str = ";".join([f"{token}:{count}" for token, count in top_tokens])
        
       
        return hashlib.sha256(token_str.encode()).hexdigest()
    
    def _generate_structural_fingerprint(self, content: str) -> str:
        """
        Generate a fingerprint based on code structure.
        
        Args:
            content: Normalized code content
            
        Returns:
            Structure-based fingerprint
        """
       
        structure = []
        
      
        for match in re.finditer(r'(?:function|def|method|class|interface)\s+\w+', content):
            structure.append(f"D:{match.group(0)}")
        
   
        for match in re.finditer(r'\b(if|else|for|while|switch|case|try|catch|finally)\b', content):
            structure.append(f"C:{match.group(0)}")
        
        
        for match in re.finditer(r'(?:var|let|const|int|float|string|bool|public|private|protected)\s+\w+', content):
            structure.append(f"V:{match.group(0)}")
        
       
        structure.sort()
        
        
        struct_str = ";".join(structure)
        
       
        return hashlib.sha256(struct_str.encode()).hexdigest()
    
    def _generate_ngram_fingerprint(self, content: str) -> str:
        """
        Generate a fingerprint based on n-grams.
        
        Args:
            content: Normalized code content
            
        Returns:
            N-gram-based fingerprint
        """
       
        tokens = tokenize_content(content)
        
        
        n = 3
        ngrams = []
        
        for i in range(len(tokens) - n + 1):
            ngram = "_".join(tokens[i:i+n])
            ngrams.append(ngram)
        
     
        counter = Counter(ngrams)
        
      
        top_ngrams = sorted(
            [(ngram, count) for ngram, count in counter.items()],
            key=lambda x: (x[1], x[0]),
            reverse=True
        )[:30]
        
     
        ngram_str = ";".join([f"{ngram}:{count}" for ngram, count in top_ngrams])
        
        
        return hashlib.sha256(ngram_str.encode()).hexdigest()
    
    def _generate_semantic_fingerprint(self, content: str) -> str:
        """
        Generate a fingerprint based on semantic properties.
        
        This is a simplified approach. In a real implementation,
        we would use a more sophisticated semantic analysis.
        
        Args:
            content: Normalized code content
            
        Returns:
            Semantic-based fingerprint
        """
       
        patterns = []
        
     
        if re.search(r'\b(open|file|read|write|fopen|fread|fwrite|readFile|writeFile)\b', content):
            patterns.append("FILE_OPS")
        
     
        if re.search(r'\b(http|socket|connect|request|curl|fetch|ajax)\b', content):
            patterns.append("NETWORK_OPS")
        
        
        if re.search(r'\b(sql|query|select|insert|update|delete|from|where|join)\b', content):
            patterns.append("DB_OPS")
        
       
        if re.search(r'\b(crypt|hash|md5|sha|aes|encrypt|decrypt)\b', content):
            patterns.append("CRYPTO_OPS")
        
     
        if re.search(r'\b(system|exec|spawn|shell|command|process)\b', content):
            patterns.append("SYS_OPS")
        
        
        if re.search(r'\b(input|prompt|read|get|post|request|param)\b', content):
            patterns.append("INPUT_OPS")
        
       
        patterns.sort()
        
       
        pattern_str = ";".join(patterns)
        
       
        return hashlib.sha256(pattern_str.encode()).hexdigest()


class SimHash:
    """
    SimHash implementation for fuzzy matching of code.
    
    SimHash is a technique that creates a fingerprint where similar
    documents are likely to have similar fingerprints, making it
    useful for fuzzy matching and near-duplicate detection.
    """
    
    def __init__(self, dimensions: int = 64, logger: Optional[logging.Logger] = None):
        """
        Initialize the SimHash generator.
        
        Args:
            dimensions: Number of dimensions in the hash (typically 64 or 128)
            logger: Logger instance
        """
        self.dimensions = dimensions
        self.logger = logger or logging.getLogger(__name__)
    
    def generate(self, content: str, normalize: bool = True) -> int:
        """
        Generate a SimHash fingerprint for code content.
        
        Args:
            content: Code content
            normalize: Whether to normalize the code
            
        Returns:
            SimHash fingerprint as an integer
        """
        if not content:
            return 0
        
        try:
           
            if normalize:
                content = self._normalize_code(content)
            
           
            tokens = tokenize_content(content)
            
           
            v = [0] * self.dimensions
            
           
            for token in tokens:
                
                token_hash = self._hash_token(token)
                
               
                for i in range(self.dimensions):
                    bit = (token_hash >> i) & 1
                    if bit:
                        v[i] += 1
                    else:
                        v[i] -= 1
            
           
            fingerprint = 0
            for i in range(self.dimensions):
                if v[i] > 0:
                    fingerprint |= (1 << i)
            
            return fingerprint
            
        except Exception as e:
            self.logger.error(f"Error generating SimHash: {e}")
            return 0
    
    def similarity(self, hash1: int, hash2: int) -> float:
        """
        Calculate the similarity between two SimHash fingerprints.
        
        Args:
            hash1: First SimHash fingerprint
            hash2: Second SimHash fingerprint
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        
        distance = self.hamming_distance(hash1, hash2)
        
        
        return 1.0 - (distance / self.dimensions)
    
    def hamming_distance(self, hash1: int, hash2: int) -> int:
        """
        Calculate the Hamming distance between two fingerprints.
        
        Args:
            hash1: First fingerprint
            hash2: Second fingerprint
            
        Returns:
            Hamming distance
        """
        xor = hash1 ^ hash2
        distance = 0
        
        while xor:
            distance += 1
            xor &= xor - 1
        
        return distance
    
    def _normalize_code(self, content: str) -> str:
        """
        Normalize code for fingerprinting.
        
        Args:
            content: Code content
            
        Returns:
            Normalized code
        """
        
        content = re.sub(r"(?://.*)|(?:/\*[\s\S]*?\*/)|(?:#.*)", "", content)
        
        
        content = re.sub(r"\s+", " ", content)
        
       
        content = re.sub(r'"([^"\\]|\\.)*"', '"STR"', content)
        content = re.sub(r"'([^'\\]|\\.)*'", "'STR'", content)
        
      
        content = re.sub(r"\b\d+\b", "NUM", content)
        
        return content.strip()
    
    def _hash_token(self, token: str) -> int:
        """
        Hash a token to an integer value.
        
        Args:
            token: Token to hash
            
        Returns:
            Hash value
        """
        hash_object = hashlib.md5(token.encode())
        hash_hex = hash_object.hexdigest()
        

        return int(hash_hex[:16], 16)
