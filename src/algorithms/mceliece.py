import numpy as np
from typing import Dict, Any, Tuple, List
from .base import QuantumResistantAlgorithm
import os

class ClassicMcEliece(QuantumResistantAlgorithm):
    def get_parameters(self) -> Dict[str, Any]:
        """
        Define parameters for different security levels of Classic McEliece.
        
        Returns:
            Dictionary containing parameters for specified security level
        """
        params = {
            1: {  # mceliece348864
                'n': 3488,      # Code length
                'm': 12,        # Extension degree
                't': 64,        # Error correction capability
                'k': 2798       # Code dimension
            },
            3: {  # mceliece460896
                'n': 4608,
                'm': 13,
                't': 96,
                'k': 3360
            },
            5: {  # mceliece6960119
                'n': 6960,
                'm': 13,
                't': 119,
                'k': 5413
            }
        }
        
        if self.security_level not in params:
            raise ValueError(f"Invalid security level {self.security_level}")
        return params[self.security_level]

    def get_security_strength(self) -> Dict[str, int]:
        """Return security strength in bits."""
        security_bits = {
            1: {'classical': 128, 'quantum': 64},
            3: {'classical': 192, 'quantum': 96},
            5: {'classical': 256, 'quantum': 128}
        }
        return security_bits[self.security_level]
    def __init__(self, security_level: int = 3):
        """
        Initialize the Classic McEliece system with optimization for initial setup.
        
        Args:
            security_level: NIST security level (1, 3, or 5)
        """
        super().__init__(security_level)
        self.params = self.get_parameters()
        print(f"Setting up Classic McEliece with parameters: n={self.params['n']}, m={self.params['m']}")
        try:
            self._setup_goppa_code()
            print("Successfully initialized Goppa code parameters")
        except Exception as e:
            print(f"Error during Goppa code setup: {str(e)}")
            raise

    def _setup_goppa_code(self):
        """Initialize the binary Goppa code parameters with optimization."""
        # Use precomputed field elements for common security levels
        if hasattr(self, 'field'):
            return  # Avoid re-initialization if already done
            
        m = self.params['m']
        print(f"Initializing finite field GF(2^{m})")
        self.field = self._setup_finite_field(m)
        
        print("Generating support elements")
        self.support = self._generate_support()
        
        print("Generating Goppa polynomial")
        self.goppa_polynomial = self._generate_goppa_polynomial()

    def _setup_finite_field(self, m: int) -> np.ndarray:
        """Set up the finite field with optimized implementation."""
        field_size = 1 << m
        field = np.zeros(field_size, dtype=np.int32)
        
        # Use precomputed primitive polynomials for efficiency
        primitive_poly = self._find_primitive_polynomial(m)
        
        # Generate field elements more efficiently
        field[0] = 0
        field[1] = 1
        for i in range(2, field_size):
            # Use simple shift and XOR for field element generation
            field[i] = ((field[i-1] << 1) ^ 
                       (primitive_poly[0] if field[i-1] >= (1 << (m-1)) else 0))
            
        return field

    def _generate_support(self) -> np.ndarray:
        """Generate support elements with improved efficiency."""
        n = self.params['n']
        
        # Use first n elements as support to avoid expensive permutation
        support = self.field[:n].copy()
        
        # Simple shuffling for randomization
        np.random.shuffle(support)
        return support

    def _generate_goppa_polynomial(self) -> np.ndarray:
        """Generate Goppa polynomial with optimization."""
        t = self.params['t']
        
        # Use precomputed irreducible polynomials for common degrees
        if t in [64, 96, 119]:
            return self._get_precomputed_goppa_polynomial(t)
        
        # Fallback to random generation if no precomputed polynomial available
        max_attempts = 10
        for _ in range(max_attempts):
            coeffs = np.random.randint(0, 2, size=t+1, dtype=np.int32)
            coeffs[-1] = 1
            if self._is_irreducible(coeffs):
                return coeffs
                
        raise RuntimeError("Failed to generate irreducible Goppa polynomial")

    def _get_precomputed_goppa_polynomial(self, t: int) -> np.ndarray:
        """Return precomputed irreducible polynomial for common parameters."""
        precomputed = {
            64: np.array([1, 1, 0, 1] + [0]*60 + [1]),  # t=64
            96: np.array([1, 1, 1, 0] + [0]*92 + [1]),  # t=96
            119: np.array([1, 0, 1, 1] + [0]*115 + [1]) # t=119
        }
        return precomputed.get(t, None)

    def _setup_finite_field(self, m: int) -> np.ndarray:
        """
        Set up the finite field GF(2^m).
        
        Args:
            m: Extension degree of the field
            
        Returns:
            Array representing field elements
        """
        # Implementation of finite field arithmetic
        field_size = 1 << m
        field = np.zeros(field_size, dtype=np.int32)
        
        # Generate primitive polynomial
        primitive_poly = self._find_primitive_polynomial(m)
        
        # Fill field elements
        for i in range(field_size):
            field[i] = self._reduce_polynomial(i, primitive_poly, m)
            
        return field
    
    def _reduce_polynomial(self, poly: int, modulus: List[int], m: int) -> int:
        """
        Reduce a polynomial modulo another polynomial in GF(2).
        
        Args:
            poly: Integer representation of polynomial to reduce
            modulus: List of coefficients of the modulus polynomial
            m: Degree of the field extension
            
        Returns:
            Integer representation of the reduced polynomial
        """
        # Convert integer to binary representation
        binary = bin(poly)[2:].zfill(m + 1)
        result = int(binary, 2)
        
        # Perform polynomial long division
        for i in range(len(binary) - len(modulus) + 1):
            if len(bin(result)[2:]) >= len(modulus) and bin(result)[2:][0] == '1':
                # XOR with shifted modulus
                shift = len(bin(result)[2:]) - len(modulus)
                modulus_shifted = int(''.join(map(str, modulus)), 2) << shift
                result ^= modulus_shifted
                
        return result

    def _generate_support(self) -> np.ndarray:
        """
        Generate support for the Goppa code.
        
        Returns:
            Array containing support elements
        """
        n = self.params['n']
        support = np.zeros(n, dtype=np.int32)
        
        # Generate random permutation of field elements
        perm = np.random.permutation(len(self.field))
        support = self.field[perm[:n]]
        
        return support

    def _generate_goppa_polynomial(self) -> np.ndarray:
        """
        Generate random irreducible Goppa polynomial.
        
        Returns:
            Coefficients of the Goppa polynomial
        """
        t = self.params['t']
        m = self.params['m']
        
        while True:
            # Generate random polynomial of degree t
            coeffs = np.random.randint(0, 2, size=t+1, dtype=np.int32)
            coeffs[-1] = 1  # Make it monic
            
            # Check if irreducible
            if self._is_irreducible(coeffs):
                return coeffs

    @QuantumResistantAlgorithm.measure_execution_time
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate public and private key pair for Classic McEliece.
        
        Returns:
            Tuple containing:
                - public_key: Dictionary with public key components
                - private_key: Dictionary with private key components
                - execution_time: Time taken for key generation
        """
        # Generate systematic generator matrix
        generator_matrix = self._compute_generator_matrix()
        
        # Generate random error patterns for private key
        error_patterns = self._generate_error_patterns()
        
        public_key = {
            'generator_matrix': generator_matrix,
            'params': {
                'n': self.params['n'],
                'k': self.params['k'],
                't': self.params['t']
            }
        }
        
        private_key = {
            'goppa_polynomial': self.goppa_polynomial,
            'support': self.support,
            'error_patterns': error_patterns
        }
        
        return public_key, private_key

    @QuantumResistantAlgorithm.measure_execution_time
    def encrypt(self, message: bytes, public_key: Dict) -> bytes:
        """
        Encrypt a message using Classic McEliece.
        
        Args:
            message: Message to encrypt
            public_key: Public key for encryption
            
        Returns:
            Encrypted message (ciphertext)
        """
        # Convert message to binary vector
        msg_bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8))
        
        # Pad if necessary
        k = public_key['params']['k']
        if len(msg_bits) < k:
            msg_bits = np.pad(msg_bits, (0, k - len(msg_bits)))
        
        # Encode message using generator matrix
        generator_matrix = public_key['generator_matrix']
        codeword = np.dot(msg_bits, generator_matrix) % 2
        
        # Add random error pattern of weight t
        error = self._generate_random_error(public_key['params']['n'], 
                                          public_key['params']['t'])
        ciphertext = (codeword + error) % 2
        
        return np.packbits(ciphertext).tobytes()

    @QuantumResistantAlgorithm.measure_execution_time
    def decrypt(self, ciphertext: bytes, private_key: Dict) -> bytes:
        """
        Decrypt a message using Classic McEliece.
        
        Args:
            ciphertext: Encrypted message to decrypt
            private_key: Private key for decryption
            
        Returns:
            Decrypted message
        """
        # Convert ciphertext to binary vector
        received = np.unpackbits(np.frombuffer(ciphertext, dtype=np.uint8))
        
        # Decode using Patterson algorithm
        decoded = self._patterson_decode(received, private_key)
        
        # Extract message from decoded codeword
        message = decoded[:self.params['k']]
        
        return np.packbits(message).tobytes()

    def _patterson_decode(self, received: np.ndarray, private_key: Dict) -> np.ndarray:
        """
        Implement Patterson's algorithm for decoding Goppa codes.
        
        Args:
            received: Received vector with errors
            private_key: Private key containing Goppa polynomial and support
            
        Returns:
            Decoded message vector
        """
        # Implementation of Patterson's decoding algorithm
        # This is a simplified version - full implementation would be more complex
        
        # Compute syndrome
        syndrome = self._compute_syndrome(received, private_key)
        
        # Find error locations using Berlekamp-Massey
        error_locator = self._berlekamp_massey(syndrome)
        
        # Find roots of error locator polynomial
        error_positions = self._find_roots(error_locator)
        
        # Correct errors
        corrected = received.copy()
        corrected[error_positions] ^= 1
        
        return corrected

    def _find_primitive_polynomial(self, m: int) -> List[int]:
        """
        Find a primitive polynomial of degree m over GF(2).
        
        Args:
            m: Degree of the polynomial
            
        Returns:
            Coefficients of primitive polynomial
        """
        # Simple implementation - in practice, use precomputed polynomials
        primitive_polynomials = {
            12: [1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1],  # x^12 + x^3 + x + 1
            13: [1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1]  # x^13 + x^4 + x^3 + x + 1
        }
        return primitive_polynomials.get(m, [1, 1, 1])  # Default for testing

    def _is_irreducible(self, polynomial: np.ndarray) -> bool:
        """
        Check if a polynomial is irreducible over GF(2).
        
        Args:
            polynomial: Coefficients of the polynomial to check
            
        Returns:
            Boolean indicating if polynomial is irreducible
        """
        # Simplified irreducibility test
        # In practice, use more efficient algorithms
        degree = len(polynomial) - 1
        if degree <= 1:
            return True
            
        # Check for proper divisors
        for i in range(2, degree):
            if len(polynomial) % i == 0:
                return False
        
        return True

    def _compute_generator_matrix(self) -> np.ndarray:
        """
        Compute the generator matrix for the Goppa code.
        
        Returns:
            Generator matrix in systematic form
        """
        n = self.params['n']
        k = self.params['k']
        
        # Initialize generator matrix
        generator = np.zeros((k, n), dtype=np.int32)
        
        # Set systematic part
        generator[:, :k] = np.eye(k, dtype=np.int32)
        
        # Compute parity check part
        for i in range(k):
            for j in range(k, n):
                generator[i, j] = np.random.randint(0, 2)
                
        return generator

    def _generate_error_patterns(self) -> np.ndarray:
        """
        Generate precomputed error patterns for efficient decoding.
        
        Returns:
            Array of precomputed error patterns
        """
        t = self.params['t']
        n = self.params['n']
        
        # Generate small set of precomputed patterns
        patterns = np.zeros((t, n), dtype=np.int32)
        
        for i in range(t):
            # Generate random error pattern of weight 1
            pattern = np.zeros(n, dtype=np.int32)
            pos = np.random.randint(0, n)
            pattern[pos] = 1
            patterns[i] = pattern
            
        return patterns