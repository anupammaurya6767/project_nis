import os
import numpy as np
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from .base import QuantumResistantAlgorithm

class Kyber(QuantumResistantAlgorithm):
    """
    Implementation of the Kyber key encapsulation mechanism.
    
    Kyber is a lattice-based KEM that is part of the NIST Post-Quantum 
    Cryptography standardization process.
    """
    
    def __init__(self, security_level: int = 3):
        """
        Initialize Kyber with specified security level.
        
        Args:
            security_level (int): NIST security level (1: Kyber512, 3: Kyber768, 5: Kyber1024)
        """
        super().__init__(security_level)
        self.params = self.get_parameters()
        self.backend = default_backend()

    def _generate_matrix_a(self, seed: bytes) -> np.ndarray:
        """
        Generate the public matrix A using a seed for deterministic randomness.
        
        This is a critical component of Kyber that generates the public matrix used
        in key generation and encapsulation. The matrix must be generated deterministically
        from the seed to ensure that both parties can reconstruct it.
        
        Args:
            seed: 32 bytes of random data to seed the generation
            
        Returns:
            Three-dimensional array representing matrix A with dimensions (k, k, n)
        """
        # Convert seed to uint32 for NumPy's random number generator
        np_seed = self._bytes_to_uint32_seed(seed)
        np.random.seed(np_seed)
        
        # Generate matrix A with dimensions k × k × n
        return np.random.randint(
            0, 
            self.params['q'], 
            size=(self.params['k'], self.params['k'], self.params['n'])
        )

    def _sample_noise(self, shape: Tuple, eta: int) -> np.ndarray:
        """
        Sample noise from a centered binomial distribution.
        
        In Kyber, noise is sampled from a centered binomial distribution to achieve
        the desired error distribution. This is crucial for the security of the scheme.
        
        Args:
            shape: Desired shape of the output array
            eta: Parameter controlling the width of the distribution
            
        Returns:
            Array of noise samples with the specified shape
        """
        # Generate 2*eta random bits for each position
        bits1 = np.random.randint(0, 2, size=(2*eta, *shape))
        bits2 = np.random.randint(0, 2, size=(2*eta, *shape))
        
        # Sum the bits and subtract to center the distribution
        return np.sum(bits1, axis=0) - np.sum(bits2, axis=0)

    def _compress(self, x: np.ndarray, d: int) -> np.ndarray:
        """
        Compress a polynomial by reducing its coefficient bit length.
        
        Compression is used to reduce the size of public keys and ciphertexts.
        It maintains security while reducing bandwidth requirements.
        
        Args:
            x: Array of coefficients to compress
            d: Number of bits to keep
            
        Returns:
            Compressed array of coefficients
        """
        factor = 2**d / self.params['q']
        return np.round(x * factor).astype(np.int64) % (2**d)

    def _decompress(self, x: np.ndarray, d: int) -> np.ndarray:
        """
        Decompress a compressed polynomial.
        
        This reverses the compression operation, expanding coefficients back to
        their full size while maintaining approximate values.
        
        Args:
            x: Array of compressed coefficients
            d: Number of bits that were kept during compression
            
        Returns:
            Decompressed array of coefficients
        """
        factor = self.params['q'] / 2**d
        return np.round(x * factor).astype(np.int64) % self.params['q']

    def get_security_strength(self) -> Dict[str, int]:
        """
        Get the security strength in bits for both classical and quantum security.
        
        Returns:
            Dictionary containing classical and quantum security strengths in bits
        """
        security_bits = {
            1: {  # Kyber512
                'classical': 128,
                'quantum': 64
            },
            3: {  # Kyber768
                'classical': 192,
                'quantum': 96
            },
            5: {  # Kyber1024
                'classical': 256,
                'quantum': 128
            }
        }
        return security_bits[self.security_level]

    def get_parameters(self) -> Dict[str, Any]:
        """
        Define parameters for different security levels of Kyber.
        
        Returns:
            Dictionary containing Kyber parameters for the specified security level
        """
        params = {
            1: {  # Kyber512
                'n': 256,
                'k': 2,
                'q': 3329,
                'eta1': 3,
                'eta2': 2,
                'du': 10,
                'dv': 4
            },
            3: {  # Kyber768
                'n': 256,
                'k': 3,
                'q': 3329,
                'eta1': 2,
                'eta2': 2,
                'du': 10,
                'dv': 4
            },
            5: {  # Kyber1024
                'n': 256,
                'k': 4,
                'q': 3329,
                'eta1': 2,
                'eta2': 2,
                'du': 11,
                'dv': 5
            }
        }
        
        if self.security_level not in params:
            raise ValueError(f"Invalid security level {self.security_level}")
        return params[self.security_level]

    def _generate_seed(self) -> bytes:
        """
        Generate a random seed for matrix generation.
        
        Returns:
            32 bytes of random data
        """
        return os.urandom(32)

    def _bytes_to_uint32_seed(self, seed: bytes) -> int:
        """
        Convert a byte string to a uint32 seed suitable for NumPy.
        
        Args:
            seed: Random bytes to use as seed
            
        Returns:
            Integer seed between 0 and 2**32 - 1
        """
        seed_int = int.from_bytes(seed[:4], byteorder='big')
        return seed_int & 0xFFFFFFFF

    @QuantumResistantAlgorithm.measure_execution_time
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate public and private key pair.
        
        Returns:
            Tuple containing:
                - public_key: Dictionary with public key components
                - private_key: Dictionary with private key components
        """
        # Similar implementation to previous version
        seed = self._generate_seed()
        A = self._generate_matrix_a(seed)
        
        # Sample secret and error vectors
        s = self._sample_noise((self.params['k'], self.params['n']), 
                             self.params['eta1'])
        e = self._sample_noise((self.params['k'], self.params['n']), 
                             self.params['eta1'])
        
        # Calculate public key t = A·s + e
        t = np.zeros((self.params['k'], self.params['n']))
        for i in range(self.params['k']):
            for j in range(self.params['k']):
                t[i] = (t[i] + np.convolve(A[i,j], s[j], 
                       mode='same')) % self.params['q']
            t[i] = (t[i] + e[i]) % self.params['q']
        
        public_key = {
            'seed': seed,
            't': t
        }
        private_key = {
            's': s
        }
        
        return public_key, private_key

    @QuantumResistantAlgorithm.measure_execution_time
    # src/algorithms/kyber.py
    def encapsulate(self, public_key: Dict) -> Tuple[Dict, bytes]:
        """
        Encapsulate a shared secret using the public key.
        """
        # Generate matrix A from seed
        A = self._generate_matrix_a(public_key['seed'])
        
        # Sample random vectors
        r = self._sample_noise((self.params['k'], self.params['n']), self.params['eta1'])
        e1 = self._sample_noise((self.params['k'], self.params['n']), self.params['eta2'])
        e2 = self._sample_noise((self.params['n'],), self.params['eta2'])
        
        # Calculate u = A^T·r + e1
        u = np.zeros((self.params['k'], self.params['n']))
        for i in range(self.params['k']):
            for j in range(self.params['k']):
                u[i] = (u[i] + np.convolve(A[j,i], r[j], mode='same')) % self.params['q']
            u[i] = (u[i] + e1[i]) % self.params['q']
        
        # Calculate v = t^T·r + e2
        v = np.zeros(self.params['n'])
        for i in range(self.params['k']):
            v = (v + np.convolve(public_key['t'][i], r[i], mode='same')) % self.params['q']
        v = (v + e2) % self.params['q']
        
        # Generate and embed shared secret
        shared_secret = os.urandom(32)
        # Expand the message to match the polynomial length
        message_bits = np.frombuffer(shared_secret, dtype=np.uint8)
        expanded_message = np.zeros(self.params['n'], dtype=np.int64)
        expanded_message[:len(message_bits)] = message_bits
        
        # Scale the message and add to v
        scaled_message = (expanded_message * (self.params['q'] // 256)) % self.params['q']
        v = (v + scaled_message) % self.params['q']
        
        return {'u': u, 'v': v}, shared_secret

    @QuantumResistantAlgorithm.measure_execution_time
    def decapsulate(self, ciphertext: Dict, private_key: Dict) -> bytes:
        """
        Decapsulate the shared secret using the private key.
        
        Args:
            ciphertext: Dictionary containing ciphertext components
            private_key: Dictionary containing private key components
            
        Returns:
            Decapsulated shared secret
        """
        # Similar to previous implementation
        v_prime = ciphertext['v'].copy()
        for i in range(self.params['k']):
            v_prime = (v_prime - np.convolve(ciphertext['u'][i], 
                      private_key['s'][i], mode='same')) % self.params['q']
        
        # Decode message
        shared_secret = np.round(v_prime * 2 / self.params['q']).astype(np.uint8)
        return shared_secret.tobytes()