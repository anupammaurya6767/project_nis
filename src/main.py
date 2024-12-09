# src/main.py
import argparse
import logging
import json
import os
import argparse
from datetime import datetime
from typing import List, Dict, Any
import time

from src.algorithms import (
    Kyber,
    Dilithium,
    FrodoKEM,
    ClassicMcEliece,
    SPHINCS
)
from src.benchmarks.performance import PerformanceBenchmark
from src.analysis.statistics import StatisticalAnalyzer
from src.analysis.visualizer import AlgorithmVisualizer
from src.utils.logger import setup_logger



class QuantumResistantAnalysis:
    def __init__(self, security_level: int = 3):
        self.security_level = security_level
        self.logger = setup_logger(__name__)
        # Create the results directory before using it
        self.results_dir = self._create_results_directory()
        
        print(f"Initializing analysis with security level {security_level}")
        print("Setting up algorithms...")
        
        try:
            self.algorithms = self._initialize_algorithms()
            print("Successfully initialized all algorithms")
        except Exception as e:
            print(f"Error during initialization: {str(e)}")
            raise

    def _create_results_directory(self) -> str:
        """
        Create and return the path to a timestamped results directory.
        This ensures each analysis run has its own unique directory for outputs.
        
        Returns:
            str: Path to the created results directory
        """
        # Create base directories if they don't exist
        base_dir = "results"
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_dir = os.path.join(base_dir, f"analysis_{timestamp}")
        
        # Create nested directories for different types of results
        subdirs = ['benchmarks', 'visualizations', 'analysis']
        for subdir in subdirs:
            full_path = os.path.join(results_dir, subdir)
            os.makedirs(full_path, exist_ok=True)
            
        print(f"Created results directory: {results_dir}")
        return results_dir

    def _save_results(self, results: Dict, filename: str):
        """
        Save analysis results to a JSON file in the results directory.
        
        Args:
            results: Dictionary containing the results to save
            filename: Name of the output file
        """
        filepath = os.path.join(self.results_dir, 'analysis', filename)
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"Successfully saved results to {filepath}")
        except Exception as e:
            print(f"Error saving results to {filepath}: {str(e)}")
            raise

    def _initialize_algorithms(self) -> List:
        """Initialize quantum-resistant algorithms with proper error handling."""
        algorithms = []
        algorithm_classes = [
            ("Kyber", Kyber),
            ("Dilithium", Dilithium),
            ("FrodoKEM", FrodoKEM),
            ("ClassicMcEliece", ClassicMcEliece)
        ]
        
        for name, algo_class in algorithm_classes:
            try:
                print(f"Initializing {name}...")
                algorithm = algo_class(self.security_level)
                algorithms.append(algorithm)
                print(f"Successfully initialized {name}")
            except Exception as e:
                print(f"Error initializing {name}: {str(e)}")
                print(f"Continuing without {name}...")
                continue
        
        if not algorithms:
            raise RuntimeError("Failed to initialize any algorithms")
        
        return algorithms

    def run_analysis(self) -> Dict[str, Any]:
        """
        Run comprehensive analysis on all initialized algorithms.
        """
        self.logger.info("Starting comprehensive analysis")
        
        try:
            # Initialize benchmark system with our algorithms
            benchmark = PerformanceBenchmark(
                algorithms=self.algorithms,
                iterations=10  # You can adjust this number based on needs
            )
            
            # Run benchmarks
            print("Running performance benchmarks...")
            results = benchmark.run_full_benchmark()
            
            # Save raw benchmark results
            self._save_results(results, 'benchmark_results.json')
            
            # Perform statistical analysis
            analyzer = StatisticalAnalyzer(results)
            stats_summary = analyzer.compute_summary_statistics()
            comparative_analysis = analyzer.perform_comparative_analysis()
            
            # Save analysis results
            self._save_results(stats_summary, 'statistical_summary.json')
            self._save_results(comparative_analysis, 'comparative_analysis.json')
            
            return {
                'benchmark_results': results,
                'statistical_summary': stats_summary,
                'comparative_analysis': comparative_analysis
            }
            
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            self.logger.error(f"Analysis failed: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(
        description='Quantum-Resistant Algorithm Analysis Tool'
    )
    parser.add_argument(
        '--security-level',
        type=int,
        choices=[1, 3, 5],
        default=3,
        help='NIST security level (1, 3, or 5)'
    )
    parser.add_argument(
        '--iterations',
        type=int,
        default=100,
        help='Number of iterations for benchmarking'
    )
    args = parser.parse_args()

    start_time = time.time()
    print(f"\nStarting analysis with:")
    print(f"Security Level: {args.security_level}")
    print(f"Iterations: {args.iterations}")
    print("\nThis analysis may take several minutes to complete...")

    try:
        analysis = QuantumResistantAnalysis(args.security_level)
        results = analysis.run_analysis()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print("\nAnalysis complete!")
        print(f"Total execution time: {execution_time:.2f} seconds")
        print("\nSummary of results:")
        print("-" * 50)
        
        for algo in results['benchmark_results']:
            print(f"\n{algo}:")
            print(f"  Key Generation Time: {results['benchmark_results'][algo]['key_generation']['mean_time']:.4f}s")
            if 'encryption' in results['benchmark_results'][algo]:
                print(f"  Encryption Time: {results['benchmark_results'][algo]['encryption']['mean_time']:.4f}s")
                print(f"  Decryption Time: {results['benchmark_results'][algo]['decryption']['mean_time']:.4f}s")
            else:
                print(f"  Signing Time: {results['benchmark_results'][algo]['signing']['mean_time']:.4f}s")
                print(f"  Verification Time: {results['benchmark_results'][algo]['verification']['mean_time']:.4f}s")
                
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        return

if __name__ == "__main__":
    main()