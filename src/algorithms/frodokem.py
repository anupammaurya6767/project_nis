from typing import Any, Dict, Tuple
import numpy as np
from .base import QuantumResistantAlgorithm
import os

class FrodoKEM(QuantumResistantAlgorithm):
    """
    Implementation of the FrodoKEM key encapsulation mechanism.
    
    FrodoKEM is a lattice-based KEM that relies on the hardness of the 
    Learning With Errors (LWE) problem. It is designed to be conservative 
    and simple to implement securely.
    """
    
    def __init__(self, security_level: int = 3):
        super().__init__(security_level)
        self.params = self.get_parameters()

    def get_security_strength(self) -> int:
        """
        Get the security strength in bits for the current security level.
        
        Returns:
            int: Security strength in bits according to NIST standards:
                - FrodoKEM-640: 128 bits (AES-128 equivalent)
                - FrodoKEM-976: 192 bits (AES-192 equivalent)
                - FrodoKEM-1344: 256 bits (AES-256 equivalent)
        """
        security_strengths = {
            1: 128,  # FrodoKEM-640
            3: 192,  # FrodoKEM-976
            5: 256   # FrodoKEM-1344
        }
        if self.security_level not in security_strengths:
            raise ValueError(f"Invalid security level {self.security_level}")
        return security_strengths[self.security_level]

    def get_parameters(self) -> Dict[str, Any]:
        """
        Define parameters for different security levels of FrodoKEM.
        
        Returns:
            Dict containing the parameters for the specified security level:
                - n: lattice dimension
                - q: modulus
                - sigma: standard deviation for error sampling
                - B: bound for secret key coefficients
                - D: bits for key/message encoding
        
        Raises:
            ValueError: If security level is not supported
        """
        params = {
            1: {  # FrodoKEM-640
                'n': 640,
                'q': 32768,
                'sigma': 2.8,
                'B': 2,
                'D': 15,
                'm': 8,    # Added: number of message bits
                'mbar': 8  # Added: dimension of message space
            },
            3: {  # FrodoKEM-976
                'n': 976,
                'q': 65536,
                'sigma': 2.3,
                'B': 4,
                'D': 16,
                'm': 8,
                'mbar': 8
            },
            5: {  # FrodoKEM-1344
                'n': 1344,
                'q': 65536,
                'sigma': 1.4,
                'B': 4,
                'D': 16,
                'm': 8,
                'mbar': 8
            }
        }
        if self.security_level not in params:
            raise ValueError(f"Invalid security level {self.security_level}")
        return params[self.security_level]

    def _sample_error(self, shape: Tuple[int, ...]) -> np.ndarray:
        """
        Sample error values from discrete Gaussian distribution.
        
        Args:
            shape: Desired shape of the error matrix/vector
            
        Returns:
            np.ndarray: Error values sampled according to discrete Gaussian
                       distribution with standard deviation sigma
        """
        return np.random.normal(0, self.params['sigma'], shape).round().astype(int)

    @QuantumResistantAlgorithm.measure_execution_time
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate FrodoKEM key pair.
        
        Returns:
            Tuple containing:
                - public_key: Dict with seed and matrix B
                - private_key: Dict with secret matrix S
        """
        n = self.params['n']
        q = self.params['q']
        
        # Generate random seed and expand to matrix A
        seed = os.urandom(32)
        np.random.seed(int.from_bytes(seed, byteorder='big'))
        A = np.random.randint(0, q, size=(n, n))
        
        # Sample secret matrix S and error matrix E
        S = np.random.randint(-self.params['B'], self.params['B'] + 1, size=(n, n))
        E = self._sample_error((n, n))
        
        # Compute B = AS + E
        B = (A @ S + E) % q
        
        public_key = {
            'seed': seed,
            'B': B
        }
        private_key = {
            'S': S
        }
        
        return public_key, private_key