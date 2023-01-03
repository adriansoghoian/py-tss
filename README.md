
### Disclaimer 

Do not use any of this code in production systems. This is strictly for educational purposes only. 

### Implementation 

This is a modified, pure-Python implementation of [Goldfeder and Gennaro's 2020 Paper](https://eprint.iacr.org/2020/540.pdf), using MPC to generate and use keys for threshold ECDSA signing / verification. 

The assumption here is that there are no adversarial parties participating in the protocol, and that we're only interested in the benefits of distributing the computation (ex. for meeting regulatory requirements around non-custody of digital assets). So, the implementation is a subset of what's in the paper (namely, many of the ZKP's used to identity / prevent malicious behavior were removed). 

Additionally, there are minimal, pure-Python implementations of some supporting primitives:

- [Paillier public key cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- Elliptic curve arithmetic helpers 
- Modular aithmetic helpers 

### Usage 

#### MPC Parameters

Configure the parameters for the MPC protocol. For example, this configuration would create a "3-of-4" thresholding signing party using key shares suitable for signing ETH transactions. 

```
from pytss.elliptic_curve import (
    secp256k1,
    secp256k1_generator,
    secp256k1_order
)
from pytss.gg20 import (
    Parameters
)

params = Parameters(
    security_parameter=256,
    paillier_security_parameter=2048,
    party_size=4,
    threshold=3,
    ec=secp256k1,
    ec_g=secp256k1_generator,
    ec_n=secp256k1_order
)
```

#### Party Participants

Next, instantiate `Participant` objects used in the key generation ceremony and in signing. Each participant has a dependency on a type conforming to the `CommunicationDelegate` interface for broadcasting messages as well as sending p2p. For demo purposes, holding the participants in memory, a sample delegate could be as simple as: 

```
from pytss.gg20 import (
    CommunicationDelegate
)

class TestDelegate(CommunicationDelegate):

    def __init__(self):
        self.participants = []

    def broadcast(self, sender_id: int, message: BaseMessage):
        for participant in self.participants:
            participant.receive_message(sender_id, message)

    def send(self, sender_id: int, recipient_id: int, message: BaseMessage):
        for participant in self.participants:
            if participant.participant_id == recipient_id:
                participant.receive_message(sender_id, message) 
```

Instantiating the `Participant` set would then look like:

```
from pytss.gg20 import (
    Participant
)

test_delegate = TestDelegate()
for i in range(1, params.party_size + 1):   
    test_delegate.participants.append(
        Participant(
            delegate=test_delegate,
            party_parameters=params,
            participant_id=i
        )
    )
```

#### Key generation 

As simple as calling the `key_gen()` function on each participant:

```
for each in participants:
    each.key_gen()
    
# read the public key from any participant
pub_key = participants[0].pub_key()
```

#### Message signing 

Since the parameters specify a 3-of-4 threshold, specify any subset of the 4 participants, and call 2 functions in turn -- `prepare_for_signing` and `sign`:

```
chosen_participant_ids = [1, 2, 3]
message = gen_random_int(0, 2 ** params.security_parameter) # msg to sign 

# call said methods on each participant. Order of calling participants does not matter.

signing_participants: List[Participant] = [ each for each in participants if each.participant_id in chosen_participant_ids ]
for each in signing_participants:
    each.prepare_for_signing(message, set(chosen_participant_ids))

for each in signing_participants:
    each.sign()
    
signature = signing_participants[0] # extract signature from any participant
```

### Installation

The majority of this project has no dependencies outside the Python 3.6+ standard library. Experimental functionality in `encoding.py` has an external dependency, captured in requirements.txt, but that's not needed for running the protocol. A `venv` directory is git-ignored by default, so feel free to use a virtual environment named as such. 

### Running Tests

The test case in test_gg20.py has an end-to-end test of the protocol, from key gen --> through to signing and verification. To run it from the project root:

`python -m unittest test.test_gg20` 

### Contributing 

Very open to any PRs covering:
- Any bug fixes
- Additional MPC-based threshold signing schemes 
- Layering in ZKPs into gg20.py
