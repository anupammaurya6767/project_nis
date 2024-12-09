import pytest
import numpy as np
from typing import Type, Any
from src.algorithms import (
    Kyber,
    Dilithium,
    FrodoKEM,
    ClassicMcEliece,
    SPHINCS,
    QuantumResistantAlgorithm
)

class TestQuantumResistantAlgorithms:
    """Comprehensive test suite for quantum-resistant algorithms."""

    @pytest.fixture(params=[1, 3, 5])
    def security_level(self, request) -> int:
        """Fixture providing different security levels."""
        return request.param

    @pytest.fixture(params=[
        Kyber,
        Dilithium,
        FrodoKEM,
        ClassicMcEliece,
        SPHINCS
    ])
    def algorithm_class(self, request) -> Type[QuantumResistantAlgorithm]:
        """Fixture providing different algorithm classes."""
        return request.param

    @pytest.fixture
    def algorithm(self, algorithm_class, security_level) -> QuantumResistantAlgorithm:
        """Fixture providing initialized algorithm instance."""
        return algorithm_class(security_level)

    def test_initialization(self, algorithm):
        """Test proper algorithm initialization."""
        assert isinstance(algorithm, QuantumResistantAlgorithm)
        assert hasattr(algorithm, 'security_level')
        assert hasattr(algorithm, 'params')
        
        # Verify parameters
        params = algorithm.get_parameters()
        assert isinstance(params, dict)
        assert len(params) > 0

    def test_security_strength(self, algorithm):
        """Test security strength reporting."""
        security = algorithm.get_security_strength()
        
        assert isinstance(security, dict)
        assert 'classical' in security
        assert 'quantum' in security
        assert security['classical'] >= security['quantum']
        
        # Verify security levels match NIST categories
        security_level_map = {
            1: {'classical': 128, 'quantum': 64},
            3: {'classical': 192, 'quantum': 96},
            5: {'classical': 256, 'quantum': 128}
        }
        expected_security = security_level_map[algorithm.security_level]
        assert security == expected_security

    def test_key_generation(self, algorithm):
        """Test key pair generation functionality."""
        public_key, private_key, time_taken = algorithm.generate_keypair()
        
        # Verify key structure
        assert isinstance(public_key, dict)
        assert isinstance(private_key, dict)
        assert len(public_key) > 0
        assert len(private_key) > 0
        
        # Verify timing information
        assert isinstance(time_taken, float)
        assert time_taken > 0

    @pytest.mark.parametrize("message_size", [16, 32, 64, 128])
    def test_encryption_scheme(self, algorithm, message_size):
        """Test encryption/decryption for KEM algorithms."""
        if hasattr(algorithm, 'encrypt'):
            # Generate test message
            message = os.urandom(message_size)
            
            # Generate keys
            public_key, private_key, _ = algorithm.generate_keypair()
            
            # Test encryption
            ciphertext, encrypt_time = algorithm.encrypt(message, public_key)
            assert isinstance(ciphertext, bytes)
            assert encrypt_time > 0
            
            # Test decryption
            decrypted, decrypt_time = algorithm.decrypt(ciphertext, private_key)
            assert isinstance(decrypted, bytes)
            assert decrypt_time > 0
            
            # Verify correctness
            assert decrypted == message

    @pytest.mark.parametrize("message_size", [16, 32, 64, 128])
    def test_signature_scheme(self, algorithm, message_size):
        """Test signing/verification for signature schemes."""
        if hasattr(algorithm, 'sign'):
            # Generate test message
            message = os.urandom(message_size)
            
            # Generate keys
            public_key, private_key, _ = algorithm.generate_keypair()
            
            # Test signing
            signature, sign_time = algorithm.sign(message, private_key)
            assert isinstance(signature, (bytes, dict))
            assert sign_time > 0
            
            # Test verification
            is_valid, verify_time = algorithm.verify(message, signature, public_key)
            assert isinstance(is_valid, bool)
            assert verify_time > 0
            
            # Verify correctness
            assert is_valid

    def test_parameter_consistency(self, algorithm):
        """Test parameter consistency across operations."""
        # Generate multiple key pairs
        pairs = [algorithm.generate_keypair() for _ in range(3)]
        
        # Verify consistent key sizes
        pub_sizes = [len(str(pair[0]).encode()) for pair in pairs]
        priv_sizes = [len(str(pair[1]).encode()) for pair in pairs]
        
        assert len(set(pub_sizes)) == 1, "Public key sizes are inconsistent"
        assert len(set(priv_sizes)) == 1, "Private key sizes are inconsistent"

    def test_error_handling(self, algorithm):
        """Test error handling in algorithm operations."""
        with pytest.raises(ValueError):
            # Test with invalid security level
            algorithm.__class__(security_level=2)
        
        public_key, private_key, _ = algorithm.generate_keypair()
        
        if hasattr(algorithm, 'encrypt'):
            with pytest.raises((ValueError, TypeError)):
                # Test with invalid message
                algorithm.encrypt(None, public_key)
            
            with pytest.raises((ValueError, TypeError)):
                # Test with invalid public key
                algorithm.encrypt(b"test", None)
        
        if hasattr(algorithm, 'sign'):
            with pytest.raises((ValueError, TypeError)):
                # Test with invalid message
                algorithm.sign(None, private_key)
            
            with pytest.raises((ValueError, TypeError)):
                # Test with invalid private key
                algorithm.sign(b"test", None)

    @pytest.mark.performance
    def test_performance_bounds(self, algorithm):
        """Test performance characteristics."""
        # Test key generation performance
        _, _, time_taken = algorithm.generate_keypair()
        
        # Define reasonable time bounds (in seconds)
        max_times = {
            'key_generation': 5.0,
            'encryption': 2.0,
            'decryption': 2.0,
            'signing': 2.0,
            'verification': 2.0
        }
        
        assert time_taken < max_times['key_generation'], \
            f"Key generation took too long: {time_taken}s"
        
        # Test operation-specific performance
        if hasattr(algorithm, 'encrypt'):
            message = b"Performance test message"
            public_key, private_key, _ = algorithm.generate_keypair()
            
            _, encrypt_time = algorithm.encrypt(message, public_key)
            assert encrypt_time < max_times['encryption'], \
                f"Encryption took too long: {encrypt_time}s"
            
            ciphertext, _ = algorithm.encrypt(message, public_key)
            _, decrypt_time = algorithm.decrypt(ciphertext, private_key)
            assert decrypt_time < max_times['decryption'], \
                f"Decryption took too long: {decrypt_time}s"
        
        if hasattr(algorithm, 'sign'):
            message = b"Performance test message"
            public_key, private_key, _ = algorithm.generate_keypair()
            
            _, sign_time = algorithm.sign(message, private_key)
            assert sign_time < max_times['signing'], \
                f"Signing took too long: {sign_time}s"
            
            signature, _ = algorithm.sign(message, private_key)
            _, verify_time = algorithm.verify(message, signature, public_key)
            assert verify_time < max_times['verification'], \
                f"Verification took too long: {verify_time}s"