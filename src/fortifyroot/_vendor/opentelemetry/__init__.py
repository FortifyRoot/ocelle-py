# Namespace package - see PEP 420
# This file intentionally left minimal for namespace package support
__path__ = __import__("pkgutil").extend_path(__path__, __name__)
