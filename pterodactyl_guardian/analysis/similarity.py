"""
Code similarity analysis for the Pterodactyl Guardian SDK.

This module provides functionality to compare code snippets and
detect similarities, helping identify variants of known malicious code.
"""

import logging
import re
import difflib
import hashlib
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from collections import Counter

from ..core.utils import tokenize_content
from ..exceptions import AnalysisError


class SimilarityAnalyzer:
    """
    Analyzer for detecting code similarities.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the similarity analyzer.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        
        self._known_samples: Dict[str, Dict[str, Any]] = {}
        
       
        self._fingerprints: Dict[str, Counter] = {}
    
    def add_known_sample(self, sample_id: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a known code sample for comparison.
        
        Args:
            sample_id: Unique identifier for the sample
            content: Code content
            metadata: Additional metadata about the sample
        """
        if not content:
            return
        
        
        self._known_samples[sample_id] = {
            "content": content,
            "metadata": metadata or {},
            "normalized": self._normalize_code(content),
            "tokens": tokenize_content(content)
        }
        
        
        self._fingerprints[sample_id] = Counter(self._get_ngrams(self._known_samples[sample_id]["tokens"], 2))
    
    def load_known_samples(self, samples: Dict[str, Dict[str, Any]]) -> None:
        """
        Load multiple known samples at once.
        
        Args:
            samples: Dictionary mapping sample IDs to sample information
        """
        for sample_id, info in samples.items():
            if "content" in info:
                self.add_known_sample(
                    sample_id=sample_id,
                    content=info["content"],
                    metadata=info.get("metadata")
                )
    
    def clear_samples(self) -> None:
        """Clear all known samples."""
        self._known_samples.clear()
        self._fingerprints.clear()
    
    def find_similarities(
        self,
        content: str,
        threshold: float = 0.7,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find similarities between content and known samples.
        
        Args:
            content: Code content to compare
            threshold: Similarity threshold (0.0 to 1.0)
            limit: Maximum number of results to return
            
        Returns:
            List of similar samples with similarity scores
        """
        if not content or not self._known_samples:
            return []
        
        try:
            
            normalized = self._normalize_code(content)
            tokens = tokenize_content(content)
            content_fingerprint = Counter(self._get_ngrams(tokens, 2))
            
           
            similarities = []
            
            
            candidates = []
            for sample_id, fingerprint in self._fingerprints.items():

                similarity = self._calculate_jaccard_similarity(content_fingerprint, fingerprint)
                
                if similarity >= threshold * 0.8:  
                    candidates.append(sample_id)
            
           
            for sample_id in candidates:
                sample = self._known_samples[sample_id]
                
               
                token_sim = self._calculate_token_similarity(tokens, sample["tokens"])
                seq_sim = self._calculate_sequence_similarity(normalized, sample["normalized"])
                
                similarity = (token_sim * 0.6) + (seq_sim * 0.4)
                
                if similarity >= threshold:
                    similarities.append({
                        "sample_id": sample_id,
                        "similarity": similarity,
                        "token_similarity": token_sim,
                        "sequence_similarity": seq_sim,
                        "metadata": sample["metadata"]
                    })
            
           
            similarities.sort(key=lambda x: x["similarity"], reverse=True)
            return similarities[:limit]
            
        except Exception as e:
            self.logger.error(f"Error finding similarities: {e}")
            raise AnalysisError(f"Failed to analyze code similarities: {e}")
    
    def _normalize_code(self, content: str) -> str:
        """
        Normalize code for comparison by removing comments,
        whitespace, and normalizing variable names.
        
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
    
    def _get_ngrams(self, tokens: List[str], n: int) -> List[str]:
        """
        Generate n-grams from a list of tokens.
        
        Args:
            tokens: List of tokens
            n: N-gram size
            
        Returns:
            List of n-grams
        """
        return ["_".join(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]
    
    def _calculate_jaccard_similarity(self, counter1: Counter, counter2: Counter) -> float:
        """
        Calculate Jaccard similarity between two Counters.
        
        Args:
            counter1: First counter
            counter2: Second counter
            
        Returns:
            Jaccard similarity (0.0 to 1.0)
        """
        set1 = set(counter1.keys())
        set2 = set(counter2.keys())
        
        if not set1 and not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_token_similarity(self, tokens1: List[str], tokens2: List[str]) -> float:
        """
        Calculate similarity based on token frequency distributions.
        
        Args:
            tokens1: First list of tokens
            tokens2: Second list of tokens
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not tokens1 or not tokens2:
            return 0.0
        
        
        counter1 = Counter(tokens1)
        counter2 = Counter(tokens2)
        
        
        common_tokens = set(counter1.keys()).intersection(set(counter2.keys()))
        
        if not common_tokens:
            return 0.0
        
      
        numerator = sum(counter1[token] * counter2[token] for token in common_tokens)
        
        
        denom1 = sum(count ** 2 for count in counter1.values()) ** 0.5
        denom2 = sum(count ** 2 for count in counter2.values()) ** 0.5
        
        return numerator / (denom1 * denom2) if denom1 * denom2 > 0 else 0.0
    
    def _calculate_sequence_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity based on longest common subsequences.
        
        Args:
            text1: First text
            text2: Second text
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not text1 or not text2:
            return 0.0
        
       
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()


class LocalitySensitiveHashing:
    """
    Locality-Sensitive Hashing for efficiently finding similar code samples.
    
    This uses MinHash and LSH to quickly identify potential matches without
    comparing against every known sample.
    """
    
    def __init__(
        self,
        num_minhashes: int = 100,
        num_bands: int = 20,
        threshold: float = 0.7,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the LSH system.
        
        Args:
            num_minhashes: Number of MinHash functions to use
            num_bands: Number of bands for LSH
            threshold: Similarity threshold (0.0 to 1.0)
            logger: Logger instance
        """
        self.num_minhashes = num_minhashes
        self.num_bands = num_bands
        self.threshold = threshold
        self.logger = logger or logging.getLogger(__name__)
        
        
        self._signatures: Dict[str, List[int]] = {}
        
       
        self._tables: List[Dict[int, List[str]]] = [{} for _ in range(num_bands)]
        
        
        self._hash_seeds = [i for i in range(num_minhashes)]
    
    def add_sample(self, sample_id: str, tokens: List[str]) -> None:
        """
        Add a sample to the LSH index.
        
        Args:
            sample_id: Sample identifier
            tokens: List of tokens from the sample
        """
        
        signature = self._generate_minhash(tokens)
        self._signatures[sample_id] = signature
        
        
        rows_per_band = self.num_minhashes // self.num_bands
        for i in range(self.num_bands):
            
            band = signature[i * rows_per_band: (i + 1) * rows_per_band]
            
            
            band_hash = hash(tuple(band))
            
            
            if band_hash not in self._tables[i]:
                self._tables[i][band_hash] = []
            self._tables[i][band_hash].append(sample_id)
    
    def find_candidates(self, tokens: List[str]) -> Set[str]:
        """
        Find candidate similar samples using LSH.
        
        Args:
            tokens: List of tokens from the query
            
        Returns:
            Set of candidate sample IDs
        """
        
        signature = self._generate_minhash(tokens)
        
        
        candidates = set()
        rows_per_band = self.num_minhashes // self.num_bands
        
        for i in range(self.num_bands):
            
            band = signature[i * rows_per_band: (i + 1) * rows_per_band]
            
           
            band_hash = hash(tuple(band))
            
            
            if band_hash in self._tables[i]:
                candidates.update(self._tables[i][band_hash])
        
        return candidates
    
    def _generate_minhash(self, tokens: List[str]) -> List[int]:
        """
        Generate a MinHash signature for a set of tokens.
        
        Args:
            tokens: List of tokens
            
        Returns:
            MinHash signature (list of integers)
        """
        
        shingles = set(self._get_ngrams(tokens, 2))
        
        
        signature = [float('inf')] * self.num_minhashes
        
        
        for shingle in shingles:
           
            shingle_hash = int(hashlib.md5(shingle.encode()).hexdigest(), 16)
            
           
            for i, seed in enumerate(self._hash_seeds):
               
                hash_value = (shingle_hash + seed) % (2**31 - 1)
                
                
                signature[i] = min(signature[i], hash_value)
        
        return signature
    
    def _get_ngrams(self, tokens: List[str], n: int) -> List[str]:
        """
        Generate n-grams from a list of tokens.
        
        Args:
            tokens: List of tokens
            n: N-gram size
            
        Returns:
            List of n-grams
        """
        return ["_".join(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]
