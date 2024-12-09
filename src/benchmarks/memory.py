import psutil
import gc
import numpy as np
from typing import Dict, List

class MemoryProfiler:
    def __init__(self):
        self.process = psutil.Process()
        self.baseline_memory = self.get_current_memory()

    def get_current_memory(self) -> int:
        gc.collect()
        return self.process.memory_info().rss

    def measure_memory_usage(self, func, *args, **kwargs) -> Dict:
        before_memory = self.get_current_memory()
        result = func(*args, **kwargs)
        after_memory = self.get_current_memory()
        
        return {
            'result': result,
            'memory_used': after_memory - before_memory,
            'peak_memory': max(after_memory, before_memory) - self.baseline_memory
        }