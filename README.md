### Installation

The majority of this project has no dependencies outside the Python 3.6+ standard library. Experimental functionality in `encoding.py` has an external dependency, captured in requirements.txt, but that's not needed for running the protocol. A `venv` directory is git-ignored by default, so feel free to use a virtual environment named as such. 

### Implementation 

This is a modified, pure-Python implementation of [Goldfeder and Gennaro's 2020 Paper](https://eprint.iacr.org/2020/540.pdf), using MPC to generate and use keys for threshold ECDSA signing / verification. 

The assumption here is that there are no adversarial parties participating in the protocol, and that we're only interested in the benefits of distributing the computation (ex. for meeting regulatory requirements around non-custody of digital assets). So, the implementation is a subset of what's in the paper (namely, many of the ZKP's used to identity / prevent malicious behavior were removed). 

Additionally, there are minimal, pure-Python implementations of some supporting primitives:

- [Paillier public key cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- Elliptic curve arithmetic helpers 
- Modular aithmetic helpers 

### Disclaimer 

Do NOT use any of this code in production systems. :) This is strictly for educational purposes, only. 

### Running Tests

The test case in test_gg20.py has an end-to-end test of the protocol, from key gen --> through to signing and verification. To run it from the project root:

`python -m unittest test.test_gg20` 

There are units tests for the various supporting functionality as well
