import math
from typing import List

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates Shannon entropy: H = -sum(p_i * log2(p_i)), range 0.0 to 8.0.
    Used across malware triage, binary section analysis, and packing detection.
    """
    if not data:
        return 0.0
    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)
