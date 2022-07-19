from typing import List
from collections import namedtuple
from .common_crypto import (
    sha256_values,
    gen_random_int
)

HashCommitmentResult = namedtuple("HashCommitmentResult", "commitment decommitment")
RANDOM_BITS_REQUIRED = 256

def _random_int() -> int:
    return gen_random_int(0, 2 ** RANDOM_BITS_REQUIRED)

def hash_commitment(values: List[any], with_randomness: bool = True): 
    inputs = values 
    if with_randomness:
        inputs.append(_random_int())
    
    commitment = sha256_values(inputs)
    return HashCommitmentResult(commitment, inputs)
    