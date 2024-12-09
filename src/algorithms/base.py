# src/algorithms/base.py

from abc import ABC, abstractmethod
import time
import os
from functools import wraps
from typing import Dict, Any, Tuple, Union, Optional

class QuantumResistantAlgorithm(ABC):
    """
    Abstract base class for quantum-resistant cryptographic algorithms.
    
    This class provides the foundation for implementing post-quantum cryptographic
    schemes, ensuring consistent interfaces and functionality across different
    implementations. It handles common operations like timing measurements and
    seed generation while defining the required interface for specific algorithms.
    """
    
    def __init__(self, security_level: int = 3):
        """
        Initialize a quantum-resistant algorithm with specified security level.
        
        Args:
            security_level: NIST security level (1, 3, or 5)
                - Level 1: equivalent to AES-128 (128-bit classical security)
                - Level 3: equivalent to AES-192 (192-bit classical security)
                - Level 5: equivalent to AES-256 (256-bit classical security)
                
        Raises:
            ValueError: If an invalid security level is provided
        """
        if security_level not in [1, 3, 5]:
            raise ValueError(
                f"Invalid security level {security_level}. "
                "Must be one of: 1 (128-bit), 3 (192-bit), or 5 (256-bit)"
            )
        self.security_level = security_level
        self.name = self.__class__.__name__

    @staticmethod
    def measure_execution_time(func):
        """
        Decorator to measure execution time of cryptographic operations.
        
        This decorator wraps cryptographic functions and measures their execution time
        using high-precision performance counter. It ensures consistent timing
        measurements across all algorithm implementations.
        
        Args:
            func: The function to be measured
            
        Returns:
            Wrapped function that includes execution time in its return value
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            # Add execution time to the result
            if isinstance(result, tuple):
                return (*result, execution_time)
            return result, execution_time
        return wrapper

    def _generate_seed(self, size: int = 32) -> bytes:
        """
        Generate a cryptographically secure random seed.
        
        This method provides a secure source of randomness for algorithm
        initialization and operations.
        
        Args:
            size: Number of bytes for the seed (default: 32 bytes/256 bits)
            
        Returns:
            Random bytes suitable for cryptographic operations
        """
        return os.urandom(size)

    def _bytes_to_uint32_seed(self, seed: bytes) -> int:
        """
        Convert a byte string to a uint32 seed suitable for NumPy.
        
        This method safely converts random bytes into a seed value that can
        be used with NumPy's random number generator.
        
        Args:
            seed: Random bytes to convert
            
        Returns:
            Integer seed between 0 and 2**32 - 1
        """
        # Take first 4 bytes and convert to integer
        seed_int = int.from_bytes(seed[:4], byteorder='big')
        # Ensure the value is within uint32 range
        return seed_int & 0xFFFFFFFF

    def _validate_key_format(self, key: Dict) -> bool:
        """
        Validate the format of a cryptographic key.
        
        This helper method ensures that keys have the required components
        and proper formatting before use in cryptographic operations.
        
        Args:
            key: Dictionary containing key components
            
        Returns:
            Boolean indicating if the key format is valid
        """
        # Implement basic key validation
        return isinstance(key, dict) and len(key) > 0

    @abstractmethod
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate a public-private key pair.
        
        This method must be implemented by each specific algorithm to generate
        appropriate key pairs according to their requirements.
        
        Returns:
            Tuple containing:
                - public_key: Dictionary with public key components
                - private_key: Dictionary with private key components
        """
        pass

    @abstractmethod
    def get_parameters(self) -> Dict[str, Any]:
        """
        Get the algorithm parameters for the current security level.
        
        This method must be implemented to provide the specific parameters
        needed for the algorithm at the chosen security level.
        
        Returns:
            Dictionary containing algorithm-specific parameters
        """
        pass

    @abstractmethod
    def get_security_strength(self) -> Dict[str, int]:
        """
        Get the security strength in bits.
        
        This method must return both classical and quantum security strengths
        for the current security level.
        
        Returns:
            Dictionary containing:
                - classical: Classical security strength in bits
                - quantum: Quantum security strength in bits
        """
        pass

    def get_key_sizes(self) -> Dict[str, int]:
        """
        Calculate the sizes of public and private keys.
        
        This helper method provides standardized size calculations across
        different implementations.
        
        Returns:
            Dictionary containing key sizes in bytes
        """
        public_key, private_key = self.generate_keypair()
        return {
            'public_key_size': len(str(public_key).encode()),
            'private_key_size': len(str(private_key).encode())
        }