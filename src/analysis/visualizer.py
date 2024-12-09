# src/analysis/visualizer.py
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import os
import numpy as np
from typing import Dict, Any

class AlgorithmVisualizer:
    """
    Comprehensive visualization tools for analyzing quantum-resistant algorithms.
    Generates various plots and charts to compare algorithm performance,
    resource usage, and security characteristics.
    """
    
    def __init__(self, results_data: Dict[str, Any]):
        """
        Initialize the visualizer with benchmark results data.
        
        Args:
            results_data: Dictionary containing benchmark results for all algorithms
        """
        self.data = results_data
        self.output_dir = "results/visualizations"
        os.makedirs(self.output_dir, exist_ok=True)
        self.setup_style()
    
    def setup_style(self):
        """Configure the visual style for all plots."""
        plt.style.use('seaborn')
        sns.set_palette("husl")
        plt.rcParams['figure.figsize'] = [12, 8]
        plt.rcParams['font.size'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12
    
    def generate_comprehensive_report(self):
        """Generate all visualizations and save them to the output directory."""
        print("Generating performance comparison plots...")
        self.plot_performance_comparison()
        
        print("Generating resource usage plots...")
        self.plot_resource_usage()
        
        print("Generating security analysis plots...")
        self.generate_security_analysis_plot()
        
        print("Generating time comparison plots...")
        self.plot_time_comparison()
        
        # Generate and save the report
        self._generate_report()
    
    def plot_performance_comparison(self):
        """Generate and save performance comparison plots."""
        metrics = ['key_generation', 'operation', 'verification']
        
        fig, axes = plt.subplots(len(metrics), 1, figsize=(12, 4*len(metrics)))
        fig.suptitle('Algorithm Performance Comparison', fontsize=16)
        
        for i, metric in enumerate(metrics):
            data = []
            labels = []
            
            for algo, results in self.data.items():
                if metric == 'operation':
                    # Handle both encryption and signing times
                    time = results.get('encryption', results.get('signing', {}))
                    time = time.get('mean_time', 0) if time else 0
                elif metric == 'verification':
                    # Handle both decryption and verification times
                    time = results.get('decryption', results.get('verification', {}))
                    time = time.get('mean_time', 0) if time else 0
                else:
                    time = results[metric]['mean_time']
                
                data.append(time)
                labels.append(algo)
            
            sns.barplot(x=labels, y=data, ax=axes[i])
            axes[i].set_title(f'{metric.replace("_", " ").title()} Time')
            axes[i].set_ylabel('Time (seconds)')
            axes[i].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'performance_comparison.png'))
        plt.close()
    
    def plot_resource_usage(self):
        """Generate and save resource usage visualization."""
        memory_data = []
        cpu_data = []
        labels = []
        
        for algo, results in self.data.items():
            if 'resource_usage' in results:
                memory_data.append(results['resource_usage'].get('memory', 0))
                cpu_data.append(results['resource_usage'].get('cpu', 0))
                labels.append(algo)
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Memory usage
        sns.barplot(x=labels, y=memory_data, ax=ax1)
        ax1.set_title('Memory Usage')
        ax1.set_ylabel('Memory (MB)')
        ax1.tick_params(axis='x', rotation=45)
        
        # CPU usage
        sns.barplot(x=labels, y=cpu_data, ax=ax2)
        ax2.set_title('CPU Usage')
        ax2.set_ylabel('CPU %')
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'resource_usage.png'))
        plt.close()
    
    def plot_time_comparison(self):
        """Generate and save time comparison across different operations."""
        operations = {
            'Key Generation': 'key_generation',
            'Encryption/Signing': ['encryption', 'signing'],
            'Decryption/Verification': ['decryption', 'verification']
        }
        
        data = []
        for algo, results in self.data.items():
            algo_times = {'Algorithm': algo}
            for op_name, op_keys in operations.items():
                if isinstance(op_keys, list):
                    # Handle combined operations
                    for key in op_keys:
                        if key in results:
                            algo_times[op_name] = results[key]['mean_time']
                            break
                else:
                    # Handle single operations
                    if op_keys in results:
                        algo_times[op_name] = results[op_keys]['mean_time']
            data.append(algo_times)
        
        df = pd.DataFrame(data)
        df.set_index('Algorithm', inplace=True)
        
        plt.figure(figsize=(12, 6))
        df.plot(kind='bar', width=0.8)
        plt.title('Time Comparison Across Operations')
        plt.ylabel('Time (seconds)')
        plt.xlabel('Algorithm')
        plt.legend(title='Operation')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        plt.savefig(os.path.join(self.output_dir, 'time_comparison.png'))
        plt.close()
    
    def _generate_report(self):
        """Generate a markdown report summarizing the analysis."""
        report_content = """# Quantum-Resistant Algorithm Analysis Report

## Overview
This report presents a comparative analysis of various quantum-resistant cryptographic algorithms.

## Performance Analysis
The performance comparison plots show the relative efficiency of each algorithm across different operations.
Key observations can be found in 'performance_comparison.png'.

## Resource Usage
Resource utilization metrics for each algorithm are visualized in 'resource_usage.png'.

## Time Comparison
A detailed comparison of operation times across algorithms is available in 'time_comparison.png'.

## Security Analysis
Security level comparisons and analysis can be found in the 'security_analysis.png'.
"""
        
        with open(os.path.join(self.output_dir, 'analysis_report.md'), 'w') as f:
            f.write(report_content)