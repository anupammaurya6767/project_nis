class SecurityAnalyzer:
    def __init__(self):
        self.security_levels = {
            'Kyber': {
                512: {'classical_bits': 128, 'quantum_bits': 64},
                768: {'classical_bits': 192, 'quantum_bits': 96},
                1024: {'classical_bits': 256, 'quantum_bits': 128}
            },
            'Dilithium': {
                2: {'classical_bits': 128, 'quantum_bits': 64},
                3: {'classical_bits': 192, 'quantum_bits': 96},
                5: {'classical_bits': 256, 'quantum_bits': 128}
            },
            'SPHINCS+': {
                128: {'classical_bits': 128, 'quantum_bits': 64},
                256: {'classical_bits': 256, 'quantum_bits': 128}
            }
        }

    def analyze_algorithm(self, algorithm_name: str, security_param: int) -> Dict:
        if algorithm_name not in self.security_levels:
            raise ValueError(f"Unknown algorithm: {algorithm_name}")
        
        if security_param not in self.security_levels[algorithm_name]:
            raise ValueError(f"Invalid security parameter for {algorithm_name}")
        
        security_info = self.security_levels[algorithm_name][security_param]
        
        return {
            'algorithm': algorithm_name,
            'security_parameter': security_param,
            'classical_security': security_info['classical_bits'],
            'quantum_security': security_info['quantum_bits'],
            'nist_category': self._get_nist_category(security_info['quantum_bits'])
        }

    def _get_nist_category(self, quantum_bits: int) -> int:
        if quantum_bits <= 64:
            return 1
        elif quantum_bits <= 96:
            return 3
        else:
            return 5
