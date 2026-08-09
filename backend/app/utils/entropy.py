import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy in bits/byte (0.0-8.0) of the given byte string.
    Plain text typically sits well under 5; generic compressed/
    encrypted/packed binary data typically sits above 7.5 - this is a
    well-established, decades-old heuristic (used by real malware
    analysis tools), not a novel detector, and it is only ever
    presented as a signal, never a verdict.
    """

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# Conventional threshold used by malware-analysis tooling for "this
# looks packed/encrypted/compressed" - not a certainty, a prompt to
# look closer. Kept as a named constant so the UI/tests reference the
# same number the backend actually used, rather than re-guessing it.
HIGH_ENTROPY_THRESHOLD = 7.2
