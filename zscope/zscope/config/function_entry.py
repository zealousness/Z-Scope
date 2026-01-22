"""
Function entry configuration for batch analysis.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FunctionEntry:
    """
    Single function entry for batch analysis.
    
    Attributes:
        function_name: Name of the function to analyze
        custom_prompt: Optional custom prompt to append to agent's base task
        file_path: Optional file path for disambiguation when multiple TUs have same function name
    """
    function_name: str
    custom_prompt: Optional[str] = None
    file_path: Optional[str] = None
    
    def __post_init__(self):
        if not self.function_name:
            raise ValueError("function_name cannot be empty")


class FunctionListLoader:
    """Load and validate function list from JSON file."""
    
    @staticmethod
    def load(json_path: Path) -> List[FunctionEntry]:
        """
        Load function entries from JSON file.
        
        Args:
            json_path: Path to JSON file containing function entries
            
        Returns:
            List of FunctionEntry objects
            
        Raises:
            FileNotFoundError: If JSON file doesn't exist
            ValueError: If JSON format is invalid
        """
        json_path = Path(json_path)
        if not json_path.exists():
            raise FileNotFoundError(f"Function list file not found: {json_path}")
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {json_path}: {e}")
        
        if not isinstance(data, dict):
            raise ValueError(f"JSON root must be an object, got {type(data).__name__}")
        
        if 'functions' not in data:
            raise ValueError("JSON must contain 'functions' array")
        
        functions_data = data['functions']
        if not isinstance(functions_data, list):
            raise ValueError(f"'functions' must be an array, got {type(functions_data).__name__}")
        
        entries = []
        for idx, func_data in enumerate(functions_data):
            if not isinstance(func_data, dict):
                logger.warning(f"Skipping invalid entry at index {idx}: not an object")
                continue
            
            try:
                entry = FunctionEntry(
                    function_name=func_data.get('function_name', ''),
                    custom_prompt=func_data.get('custom_prompt'),
                    file_path=func_data.get('file_path')
                )
                entries.append(entry)
                logger.debug(f"Loaded function entry: {entry.function_name}")
            except ValueError as e:
                logger.warning(f"Skipping invalid entry at index {idx}: {e}")
                continue
        
        if not entries:
            raise ValueError("No valid function entries found in JSON file")
        
        logger.info(f"Loaded {len(entries)} function entries from {json_path}")
        return entries
