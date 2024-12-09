# src/benchmarks/performance.py
import numpy as np
from typing import List, Dict, Any
import time

class PerformanceBenchmark:
    """
    A comprehensive benchmarking system for quantum-resistant cryptographic algorithms.
    This class provides methods to measure and analyze the performance characteristics
    of both Key Encapsulation Mechanisms (KEMs) and digital signature schemes.
    """
    
    def __init__(self, algorithms: List = None, iterations: int = 100):
        """
        Initialize the benchmark system with specified algorithms and parameters.
        
        Args:
            algorithms: List of algorithm instances to benchmark
            iterations: Number of times to repeat each measurement for statistical significance
        """
        self.algorithms = algorithms if algorithms is not None else []
        self.iterations = iterations
        self.results = {}
        print(f"Initialized benchmark system with {len(self.algorithms)} algorithms")
        print(f"Each operation will be repeated {self.iterations} times for accuracy")

    def _benchmark_key_generation(self, algorithm) -> Dict[str, float]:
        """
        Measures the performance of key generation operations. This method repeatedly
        generates key pairs and measures both the execution time and resulting key sizes.
        
        Args:
            algorithm: The cryptographic algorithm instance to benchmark
            
        Returns:
            Dictionary containing timing and size statistics for key generation
        """
        print(f"\nMeasuring key generation performance...")
        times = []
        key_sizes = []
        
        for i in range(self.iterations):
            print(f"  Progress: {i+1}/{self.iterations}", end='\r')
            
            # Generate keys and measure time
            keypair_result = algorithm.generate_keypair()
            
            # Extract timing information and keys
            if len(keypair_result) == 3:  # If timing decorator added execution time
                public_key, private_key, execution_time = keypair_result
            else:  # Handle case where timing might not be included
                public_key, private_key = keypair_result
                execution_time = 0
                
            times.append(execution_time)
            
            # Measure key sizes
            pub_size = len(str(public_key).encode())
            priv_size = len(str(private_key).encode())
            key_sizes.append((pub_size, priv_size))
        
        print("\nCompleted key generation measurements")
        
        return {
            'mean_time': np.mean(times),
            'std_time': np.std(times),
            'mean_public_key_size': np.mean([k[0] for k in key_sizes]),
            'mean_private_key_size': np.mean([k[1] for k in key_sizes])
        }

    def _benchmark_kem(self, algorithm) -> Dict[str, Dict[str, float]]:
        """
        Measures the performance of Key Encapsulation Mechanism operations.
        This includes both encapsulation and decapsulation processes.
        
        Args:
            algorithm: The KEM algorithm instance to benchmark
            
        Returns:
            Dictionary containing timing and size statistics for KEM operations
        """
        print("\nMeasuring KEM operations performance...")
        encap_times = []
        decap_times = []
        ciphertext_sizes = []
        
        # Generate a keypair for testing
        public_key, private_key, _ = algorithm.generate_keypair()
        
        for i in range(self.iterations):
            print(f"  Progress: {i+1}/{self.iterations}", end='\r')
            
            # Measure encapsulation
            try:
                encap_result = algorithm.encapsulate(public_key)
                if len(encap_result) == 3:
                    ciphertext, shared_secret, encap_time = encap_result
                else:
                    ciphertext, shared_secret = encap_result
                    encap_time = 0
                encap_times.append(encap_time)
                
                # Measure decapsulation
                decap_result = algorithm.decapsulate(ciphertext, private_key)
                if len(decap_result) == 2:
                    decrypted_secret, decap_time = decap_result
                else:
                    decrypted_secret = decap_result
                    decap_time = 0
                decap_times.append(decap_time)
                
                ciphertext_sizes.append(len(str(ciphertext).encode()))
            except Exception as e:
                print(f"\nError during KEM operation: {str(e)}")
                continue
        
        print("\nCompleted KEM measurements")
        
        return {
            'encapsulation': {
                'mean_time': np.mean(encap_times),
                'std_time': np.std(encap_times)
            },
            'decapsulation': {
                'mean_time': np.mean(decap_times),
                'std_time': np.std(decap_times)
            },
            'ciphertext_size': np.mean(ciphertext_sizes)
        }

    def _benchmark_signing(self, algorithm) -> Dict[str, Dict[str, float]]:
        """
        Measures the performance of digital signature operations.
        This includes both signature generation and verification processes.
        
        Args:
            algorithm: The signature scheme algorithm instance to benchmark
            
        Returns:
            Dictionary containing timing and size statistics for signature operations
        """
        print("\nMeasuring signature operations performance...")
        sign_times = []
        verify_times = []
        signature_sizes = []
        message = b"Test message for benchmarking digital signatures"
        
        # Generate a keypair for testing
        public_key, private_key, _ = algorithm.generate_keypair()
        
        for i in range(self.iterations):
            print(f"  Progress: {i+1}/{self.iterations}", end='\r')
            
            try:
                # Measure signature generation
                sign_result = algorithm.sign(message, private_key)
                if len(sign_result) == 2:
                    signature, sign_time = sign_result
                else:
                    signature = sign_result
                    sign_time = 0
                sign_times.append(sign_time)
                
                # Measure signature verification
                verify_result = algorithm.verify(message, signature, public_key)
                if len(verify_result) == 2:
                    is_valid, verify_time = verify_result
                else:
                    is_valid = verify_result
                    verify_time = 0
                verify_times.append(verify_time)
                
                signature_sizes.append(len(str(signature).encode()))
            except Exception as e:
                print(f"\nError during signature operation: {str(e)}")
                continue
                
        print("\nCompleted signature measurements")
        
        return {
            'signing': {
                'mean_time': np.mean(sign_times),
                'std_time': np.std(sign_times)
            },
            'verification': {
                'mean_time': np.mean(verify_times),
                'std_time': np.std(verify_times)
            },
            'signature_size': np.mean(signature_sizes)
        }

    def run_full_benchmark(self) -> Dict[str, Any]:
        """
        Executes a comprehensive benchmark suite for all registered algorithms.
        This method automatically detects the algorithm type (KEM or signature scheme)
        and runs appropriate benchmarks.
        
        Returns:
            Dictionary containing all benchmark results for all algorithms
        """
        print("\nStarting comprehensive benchmark suite...")
        
        for algorithm in self.algorithms:
            print(f"\nBenchmarking algorithm: {algorithm.name}")
            
            # Benchmark key generation for all algorithms
            try:
                key_gen_results = self._benchmark_key_generation(algorithm)
                self.results[algorithm.name] = {'key_generation': key_gen_results}
                
                # Determine algorithm type and run appropriate benchmarks
                if hasattr(algorithm, 'sign'):
                    signing_results = self._benchmark_signing(algorithm)
                    self.results[algorithm.name].update(signing_results)
                elif hasattr(algorithm, 'encapsulate'):
                    kem_results = self._benchmark_kem(algorithm)
                    self.results[algorithm.name].update(kem_results)
                    
            except Exception as e:
                print(f"Error benchmarking {algorithm.name}: {str(e)}")
                continue
        
        print("\nBenchmark suite completed")
        return self.results