class Config:
    # Algorithm configurations
    ALGORITHMS = {
        'Kyber': {
            'security_levels': [512, 768, 1024],
            'default_level': 512
        },
        'Dilithium': {
            'security_levels': [2, 3, 5],
            'default_level': 2
        },
        'SPHINCS+': {
            'security_levels': [128, 256],
            'default_level': 128
        }
    }
    
    # Benchmark configurations
    BENCHMARK = {
        'iterations': 100,
        'warmup_iterations': 10,
        'message_sizes': [64, 128, 256, 512, 1024],  # in bytes
        'timeout': 300  # seconds
    }
    
    # Analysis configurations
    ANALYSIS = {
        'metrics': ['time', 'memory', 'cpu'],
        'percentiles': [50, 95, 99],
        'plot_format': 'png'
    }
    
    # Logging configurations
    LOGGING = {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'data/logs/benchmark.log'
    }