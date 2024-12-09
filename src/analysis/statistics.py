import numpy as np
import pandas as pd
from typing import Dict, List, Any
import scipy.stats as stats

class StatisticalAnalyzer:
    def _convert_to_serializable(self, obj):
        """Convert NumPy types to Python native types."""
        if isinstance(obj, np.float64):
            return float(obj)
        elif isinstance(obj, np.int64):
            return int(obj)
        elif isinstance(obj, dict):
            return {k: self._convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_serializable(x) for x in obj]
        return obj

    def compute_summary_statistics(self) -> Dict[str, Any]:
        """Compute summary statistics with proper serialization."""
        summary = {}
        
        for algorithm_name, results in self.data.items():
            summary[algorithm_name] = {}
            for operation, metrics in results.items():
                summary[algorithm_name][operation] = self._convert_to_serializable(metrics)
        
        return summary

    def perform_comparative_analysis(self) -> Dict[str, Any]:
        """Perform comparative analysis with proper serialization."""
        results = {}
        
        for metric_name, values in self.metrics.items():
            results[metric_name] = self._convert_to_serializable(values)
            
        return results
    
    def __init__(self, benchmark_data: Dict[str, Any]):
        self.data = benchmark_data
        self.metrics = self._extract_metrics()

    def _extract_metrics(self) -> Dict[str, pd.DataFrame]:
        """Extract and organize metrics from benchmark data."""
        metrics = {}
        
        # Time metrics
        time_data = {
            algo: {
                'key_gen_time': data['key_generation']['mean_time'],
                'operation_time': data.get('encryption', data.get('signing', {})).get('mean_time', np.nan),
                'verification_time': data.get('decryption', data.get('verification', {})).get('mean_time', np.nan)
            }
            for algo, data in self.data.items()
        }
        metrics['time'] = pd.DataFrame(time_data).T
        
        # Size metrics
        size_data = {
            algo: {
                'public_key_size': data['key_generation']['mean_public_key_size'],
                'private_key_size': data['key_generation']['mean_private_key_size'],
                'output_size': data.get('ciphertext_size', data.get('signature_size', np.nan))
            }
            for algo, data in self.data.items()
        }
        metrics['size'] = pd.DataFrame(size_data).T
        
        return metrics