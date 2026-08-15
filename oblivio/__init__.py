"""Oblivio — privacy-preserving AI memory infrastructure.

Clients encrypt locally. Nodes store ciphertext they cannot read, committed to
an append-only Merkle log they cannot rewrite undetected. The current release
does not call cloud LLM APIs and does not depend on SNARKs.

See the repository README, CONTRIBUTING.md, and THESIS.md for product scope.
"""

__version__ = "0.1.0"
