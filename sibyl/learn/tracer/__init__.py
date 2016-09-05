"""This package provides methods for tracing a program and retrieving:
- executed instructions
- memory accesses
"""

from sibyl.learn.tracer.pin import TracerPin
from sibyl.learn.tracer.miasm import TracerMiasm

AVAILABLE_TRACER = {
    "pin": TracerPin,
    "miasm": TracerMiasm
}

__all__ = ["AVAILABLE_TRACER"]
