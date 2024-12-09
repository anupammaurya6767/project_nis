import numpy as np
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives import hashes
from .base import QuantumResistantAlgorithm
import os

class Dilithium(QuantumResistantAlgorithm):
    """
    Implementation of the Dilithium digital signature scheme.
    
    Dilithium is a lattice-based signature scheme offering quantum resistance.
    It maps NIST security levels to Dilithium variants:
    - NIST Level 1 → Dilithium2 (128-bit classical security)
    - NIST Level 3 → Dilithium3 (192-bit classical security)
    - NIST Level 5 → Dilithium5 (256-bit classical security)
    """
    
    def __init__(self, security_level: int = 3):
        """
        Initialize Dilithium with specified security level.
        
        Args:
            security_level: NIST security level (1, 3, or 5)
        """
        # Map NIST levels to Dilithium variants
        self.nist_to_dilithium = {
            1: 2,  # NIST Level 1 → Dilithium2
            3: 3,  # NIST Level 3 → Dilithium3
            5: 5   # NIST Level 5 → Dilithium5
        }
        
        if security_level not in self.nist_to_dilithium:
            raise ValueError(
                f"Invalid NIST security level {security_level}. "
                f"Choose from: {list(self.nist_to_dilithium.keys())}"
            )
        
        super().__init__(security_level)
        self.dilithium_level = self.nist_to_dilithium[security_level]
        self.params = self.get_parameters()

    def get_parameters(self) -> Dict[str, Any]:
        """Define parameters for each Dilithium variant."""
        params = {
            2: {  # Dilithium2
                'k': 4,     # Number of matrix rows
                'l': 4,     # Number of matrix columns
                'd': 13,    # Dropped bits in high bits
                'eta': 2,   # Coefficient range for secret vectors
                'gamma1': 1 << 17,  # Range for large coefficients
                'gamma2': (1 << 17) // 2,  # Range for small coefficients
                'tau': 39,  # Number of +1/-1 coefficients
                'q': 8380417,  # Modulus
                'n': 256,   # Ring dimension
                'beta': 78  # Rejection bound
            },
            3: {  # Dilithium3
                'k': 6,
                'l': 5,
                'd': 13,
                'eta': 4,
                'gamma1': 1 << 19,
                'gamma2': (1 << 19) // 2,
                'tau': 49,
                'q': 8380417,
                'n': 256,
                'beta': 196
            },
            5: {  # Dilithium5
                'k': 8,
                'l': 7,
                'd': 13,
                'eta': 2,
                'gamma1': 1 << 19,
                'gamma2': (1 << 19) // 2,
                'tau': 60,
                'q': 8380417,
                'n': 256,
                'beta': 120
            }
        }
        return params[self.dilithium_level]

    def get_security_strength(self) -> Dict[str, int]:
        """Get classical and quantum security strengths in bits."""
        security_strengths = {
            2: {'classical': 128, 'quantum': 64},  # Dilithium2
            3: {'classical': 192, 'quantum': 96},  # Dilithium3
            5: {'classical': 256, 'quantum': 128}  # Dilithium5
        }
        return security_strengths[self.dilithium_level]

    def _generate_matrix_a(self, seed: bytes) -> np.ndarray:
        """
        Generate the public matrix A using a seed.
        
        Args:
            seed: Random seed for matrix generation
            
        Returns:
            Three-dimensional array representing matrix A
        """
        np.random.seed(int.from_bytes(seed, byteorder='big'))
        return np.random.randint(
            0, self.params['q'],
            size=(self.params['k'], self.params['l'], self.params['n'])
        )

    def _sample_in_ball(self, tau: int, seed: int) -> np.ndarray:
        """
        Sample a polynomial with exactly tau +1's and tau -1's.
        
        Args:
            tau: Number of each non-zero coefficient
            seed: Random seed for sampling
            
        Returns:
            Array representing the polynomial
        """
        np.random.seed(seed)
        n = self.params['n']
        c = np.zeros(n, dtype=int)
        
        # Generate positions for +1s
        pos_ones = np.random.choice(n, tau, replace=False)
        c[pos_ones] = 1
        
        # Generate positions for -1s
        remaining_pos = np.setdiff1d(np.arange(n), pos_ones)
        neg_ones = np.random.choice(remaining_pos, tau, replace=False)
        c[neg_ones] = -1
        
        return c

    @QuantumResistantAlgorithm.measure_execution_time
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate Dilithium public-private key pair.
        
        Returns:
            Tuple containing public and private key dictionaries
        """
        # Generate random seed for matrix A
        seed = os.urandom(32)
        A = self._generate_matrix_a(seed)
        
        # Generate secret vectors s1 and s2
        s1 = np.random.randint(
            -self.params['eta'],
            self.params['eta'] + 1,
            size=(self.params['l'], self.params['n'])
        )
        s2 = np.random.randint(
            -self.params['eta'],
            self.params['eta'] + 1,
            size=(self.params['k'], self.params['n'])
        )
        
        # Calculate public key t = A·s1 + s2
        t = np.zeros((self.params['k'], self.params['n']))
        for i in range(self.params['k']):
            for j in range(self.params['l']):
                t[i] = (t[i] + np.convolve(
                    A[i,j], s1[j], mode='same'
                )) % self.params['q']
            t[i] = (t[i] + s2[i]) % self.params['q']
        
        public_key = {
            'seed': seed,
            't': t
        }
        private_key = {
            's1': s1,
            's2': s2
        }
        
        return public_key, private_key

    @QuantumResistantAlgorithm.measure_execution_time
    def sign(self, message: bytes, private_key: Dict) -> Dict:
        """
        Sign a message using Dilithium.
        
        Args:
            message: Message to sign
            private_key: Private key for signing
            
        Returns:
            Dictionary containing signature components
        """
        s1 = private_key['s1']
        s2 = private_key['s2']
        
        # Generate commitment randomness
        y = np.random.randint(
            -self.params['gamma1'],
            self.params['gamma1'] + 1,
            size=(self.params['l'], self.params['n'])
        )
        
        # Calculate challenge
        hasher = hashes.Hash(hashes.SHA3_256())
        hasher.update(message + y.tobytes())
        c = self._sample_in_ball(
            self.params['tau'],
            int.from_bytes(hasher.finalize(), byteorder='big')
        )
        
        # Calculate response z = y + c·s1
        z = y.copy()
        for i in range(self.params['l']):
            z[i] = (z[i] + np.convolve(
                c, s1[i], mode='same'
            )) % self.params['q']
        
        # Perform rejection sampling
        if np.any(np.abs(z) >= self.params['gamma1'] - self.params['beta']):
            # If rejected, try again with new randomness
            return self.sign(message, private_key)
        
        return {
            'z': z,
            'c': c
        }

    @QuantumResistantAlgorithm.measure_execution_time
    def verify(self, message: bytes, signature: Dict, public_key: Dict) -> bool:
        """
        Verify a Dilithium signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key for verification
            
        Returns:
            Boolean indicating signature validity
        """
        z = signature['z']
        c = signature['c']
        t = public_key['t']
        
        # Verify z is in correct range
        if np.any(np.abs(z) >= self.params['gamma1'] - self.params['beta']):
            return False
        
        # Reconstruct challenge
        hasher = hashes.Hash(hashes.SHA3_256())
        hasher.update(message + z.tobytes())
        c_prime = self._sample_in_ball(
            self.params['tau'],
            int.from_bytes(hasher.finalize(), byteorder='big')
        )
        
        return np.array_equal(c, c_prime)