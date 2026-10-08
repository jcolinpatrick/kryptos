"""Public-reproduction shim for cryptolab.research_bridge.k4.

The original module also builds research records and provenance labels that the DOT-STANDING
searches never touch. Only the two names the probes import are provided, and the ciphertext is
checked against the canonical SHA-256 used by every campaign spec.
"""
import hashlib

K4_CIPHERTEXT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_SHA256 = "eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab"
assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest() == K4_SHA256
