"""This package provides methods for automaticly creating new test case for Sibyl
"""
"""This package provides methods for tracing a program and retrieving:
- executed instructions
- memory accesses
"""

from sibyl.learn.generator.pythongenerator import PythonGenerator

AVAILABLE_GENERATOR = {
    "python": PythonGenerator,
}

__all__ = ["AVAILABLE_GENERATOR"]
