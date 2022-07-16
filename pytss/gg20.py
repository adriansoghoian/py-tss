from typing import List, Mapping, Optional
import abc
import logging
from collections import namedtuple
from pytss.common_crypto import (
    gen_random_int
)
from pytss.paillier import (
    PaillierPublicKey,
    generate_key_pair
)
from pytss.common_math import (
    compute_modular_inverse
)
from pytss.elliptic_curve import (
    EllipticCurve,
    Point,
    Signature
)
from pytss.secret_sharing import (
    split_into_shares
)
from dataclasses import dataclass, replace, asdict

# Implementation taken from https://eprint.iacr.org/2020/540.pdf

logger = logging.getLogger(__name__)

# Party Parameters
@dataclass
class Parameters:

    security_parameter: int
    paillier_security_parameter: int
    party_size: int
    threshold: int
    ec: EllipticCurve
    ec_g: Point
    ec_n: int

# Message holders
class BaseMessage: pass 

@dataclass
class KeyGenBroadcast(BaseMessage):
    y: Point
    paillier_pk: PaillierPublicKey
    vss_shares: List[Point]

@dataclass
class KeyGenP2P(BaseMessage):
    shamir_share: int

@dataclass
class MtoAP2P1(BaseMessage):
    encrypted_value: int

@dataclass
class MtoAP2P1Response(BaseMessage):
    cipher_b: int

@dataclass
class MtoABroadcast1(BaseMessage):
    gamma_elliptic: Point

@dataclass 
class MtoAP2P2(BaseMessage):
    encrypted_value: int

@dataclass 
class MtoAP2P2Response(BaseMessage):
    encrypted_value: int

@dataclass 
class SigningPostMtoABroadcast(BaseMessage):
    delta_i: int
    gamma_elliptic: Point

@dataclass 
class SigningShare(BaseMessage):
    share: int

# Class to facilitate broadcast messages as well as p2p    
class CommunicationDelegate(metaclass=abc.ABCMeta): 

    @abc.abstractmethod
    def broadcast(self, sender_id: int, message: BaseMessage):
        raise NotImplementedError

    @abc.abstractmethod
    def send(self, sender_id: int, recipient_id: int, message: BaseMessage):
        raise NotImplementedError

@dataclass
class KeyGenState:
    paillier_public_key: PaillierPublicKey
    paillier_secret_key: PaillierPublicKey
    secret_key_share: int
    ec_g: Point
    curve: EllipticCurve

    secret_key_shamir_shares: List[tuple[int, int]]
    secret_key_vss_shares: List[Point]

    y: Point
    x: int
    big_x: Point 

    other_y_by_id: Mapping[int, Point]
    other_shamir_shares_by_id: Mapping[int, int]
    other_paillier_public_keys_by_id: Mapping[int, PaillierPublicKey]
    
    other_big_x_by_ids: Mapping[int, Point]

@dataclass
class SigningState:
    w: int
    k: int

    gamma: int
    gamma_elliptic: Point 
    gamma_elliptic_summation: Point

    signer_ids: set[int]

    delta_i: int
    delta: int
    delta_by_id: Mapping[int, int]

    sigma: int
    sigma_i: int
    little_r: int

    s_by_id: int

    big_w_by_id: Mapping[int, Point]

    mToA_outputs_as_initiator_1: Mapping[int, int]
    mToA_outputs_as_receiver_1: Mapping[int, int]

    mToA_outputs_as_initiator_2: Mapping[int, int]
    mToA_outputs_as_receiver_2: Mapping[int, int]

class Participant():

    def __init__(
        self,
        participant_id: int,
        delegate: CommunicationDelegate,
        party_parameters: Parameters
    ): 
        self.participant_id = participant_id
        self.delegate = delegate
        self.party_parameters = party_parameters

        # Protocol state 
        # Key generation
        self.key_gen_state: KeyGenState = KeyGenState(
            ec_g=self.party_parameters.ec_g,
            curve=self.party_parameters.ec,
            paillier_public_key=None,
            paillier_secret_key=None,
            x=None,
            big_x=None,
            secret_key_share=None,
            secret_key_shamir_shares=[],
            secret_key_vss_shares=[],
            y=None,
            other_y_by_id={},
            other_shamir_shares_by_id={},
            other_paillier_public_keys_by_id={},
            other_big_x_by_ids={}
        )

        # Signing 
        self.signing_state: Optional[SigningState] = None

    def _update_key_gen_state(self, **kwargs):
        self.key_gen_state = replace(self.key_gen_state, **kwargs)

    def key_gen(self):
        logger.debug(f'Partipant {self.participant_id}: generating key...')
        # Generate Paillier keypair
        paillier_pub_key, paillier_sec_key = generate_key_pair(
            self.party_parameters.paillier_security_parameter
        )
        self._update_key_gen_state(
            paillier_public_key=paillier_pub_key,
            paillier_secret_key=paillier_sec_key
        )

        # Generate private keyshare 
        secret_key_share = gen_random_int(1, self.party_parameters.ec_n)
        self._update_key_gen_state(
            secret_key_share=secret_key_share
        )

        # Split into t, n shamir shares 
        shamir_shares = split_into_shares(
            secret_key_share, 
            self.party_parameters.party_size, 
            self.party_parameters.threshold,
            self.party_parameters.ec_n
        )

        self._update_key_gen_state(
            secret_key_shamir_shares=shamir_shares
        )

        # Compute y for this participant
        y = secret_key_share * self.party_parameters.ec_g
        self._update_key_gen_state(
            y=y
        )

        # Compute feldman VSS shares
        vss_shares = []
        for i in range(len(shamir_shares)):
            shamir_share = shamir_shares[i][1]
            vss_share = shamir_share * self.party_parameters.ec_g
            vss_shares.append(vss_share)

        self._update_key_gen_state(
            secret_key_vss_shares=vss_shares
        )

        # broadcast and send 
        # broadcast yi, public value, EC scalar multiplication value 
        # of secret share * EC generator point
        self.delegate.broadcast(
            self.participant_id,
            KeyGenBroadcast(y, paillier_pub_key, vss_shares)
        )

        # P2P send shamir secret share of private key share
        for recipient_id in range(1, self.party_parameters.party_size + 1):
            shamir_share = shamir_shares[recipient_id - 1]
            self.delegate.send(
                self.participant_id,
                recipient_id,
                KeyGenP2P(shamir_share[1])
            )

        
    def public_key(self) -> Point: 
        assert len(self.key_gen_state.other_y_by_id) == self.party_parameters.party_size

        public_key = Point(x=None, y=None, curve=self.party_parameters.ec)
        for each in self.key_gen_state.other_y_by_id.values():
            public_key += each

        return public_key

    def signature(self) -> Signature:
        assert len(self.signing_state.s_by_id) == len(self.signing_state.signer_ids)

        r = self.signing_state.little_r
        s = sum(self.signing_state.s_by_id.values())

        return Signature(
            r=r, 
            s=s, 
            G=self.party_parameters.ec_g, 
            N=self.party_parameters.ec_n
        )

    def receive_message(self, sender_id: int, message: BaseMessage):
        if isinstance(message, KeyGenBroadcast):
            self.key_gen_state.other_y_by_id[sender_id] = message.y
            self.key_gen_state.other_paillier_public_keys_by_id[sender_id] = message.paillier_pk

        elif isinstance(message, KeyGenP2P):
            self.key_gen_state.other_shamir_shares_by_id[sender_id] = message.shamir_share

            if len(self.key_gen_state.other_shamir_shares_by_id) == self.party_parameters.party_size:
                self.key_gen_state.x = sum(self.key_gen_state.other_shamir_shares_by_id.values())
                self.key_gen_state.big_x = self.key_gen_state.x * self.party_parameters.ec_g

        elif isinstance(message, MtoAP2P1):
            sender_pk = self.key_gen_state.other_paillier_public_keys_by_id[sender_id]

            beta_prime = gen_random_int(1, 2 ** (5 * self.party_parameters.security_parameter))
            beta = (-1) * beta_prime % self.party_parameters.ec_n

            cipher_b_left = sender_pk.homomorphic_multiply(message.encrypted_value, self.signing_state.gamma)
            cipher_b = sender_pk.homomorphic_add(cipher_b_left, beta_prime)
            
            self.signing_state.mToA_outputs_as_receiver_1[sender_id] = beta
            self.delegate.send(
                self.participant_id,
                sender_id,
                MtoAP2P1Response(cipher_b)
            )

        elif isinstance(message, MtoAP2P1Response):
            decrypted = self.key_gen_state.paillier_secret_key.decrypt(message.cipher_b)
            alpha = decrypted % self.party_parameters.ec_n
            self.signing_state.mToA_outputs_as_initiator_1[sender_id] = alpha

        elif isinstance(message, MtoAP2P2):
            sender_pk = self.key_gen_state.other_paillier_public_keys_by_id[sender_id]

            beta_prime = gen_random_int(1, 2 ** (5 * self.party_parameters.security_parameter))
            beta = (-1) * beta_prime % self.party_parameters.ec_n

            cipher_b_left = sender_pk.homomorphic_multiply(message.encrypted_value, self.signing_state.w)
            cipher_b = sender_pk.homomorphic_add(cipher_b_left, beta_prime)
            
            self.signing_state.mToA_outputs_as_receiver_2[sender_id] = beta
            self.delegate.send(
                self.participant_id,
                sender_id,
                MtoAP2P2Response(cipher_b)
            )

        elif isinstance(message, MtoAP2P2Response):
            decrypted = self.key_gen_state.paillier_secret_key.decrypt(message.encrypted_value)
            alpha = decrypted % self.party_parameters.ec_n
            self.signing_state.mToA_outputs_as_initiator_2[sender_id] = alpha

        elif isinstance(message, SigningPostMtoABroadcast):
            if not self.signing_state:
                return 

            self.signing_state.delta_by_id[sender_id] = message.delta_i
            if len(self.signing_state.delta_by_id) == len(self.signing_state.signer_ids):
                self.signing_state.delta = sum(self.signing_state.delta_by_id.values()) % self.party_parameters.ec_n

            if self.signing_state.gamma_elliptic_summation is None:
                self.signing_state.gamma_elliptic_summation = Point(x=None, y=None, curve=self.party_parameters.ec)

            self.signing_state.gamma_elliptic_summation += message.gamma_elliptic

        elif isinstance(message, SigningShare):
            if not self.signing_state:
                return 

            self.signing_state.s_by_id[sender_id] = message.share

    def signing_part1(self, signer_ids: set[int]) -> Signature:
        assert self.participant_id in signer_ids
        logger.debug(f'Partipant {self.participant_id}: signing part 1')

        # reset signing state 
        self.signing_state = SigningState(
            w=None,
            k=None,
            gamma=None,
            sigma=None,
            sigma_i=None,
            signer_ids=signer_ids,
            gamma_elliptic=None,
            gamma_elliptic_summation=None,
            big_w_by_id={},
            delta=None,
            delta_i=None,
            delta_by_id={},
            little_r=None,
            s_by_id={},
            mToA_outputs_as_initiator_1={},
            mToA_outputs_as_receiver_1={},
            mToA_outputs_as_initiator_2={},
            mToA_outputs_as_receiver_2={}
        )

        # Convert (t, n) private share x_i of x into a (t, t+1) share of x, w_i, where 
        # sum(all(w_i)) == x (private key)
        big_w_by_id: Mapping[int, Point] = {}
        q = self.party_parameters.ec_n

        w = self.key_gen_state.x
        for i in signer_ids:
            if i == self.participant_id: continue 
            w = (w * i * compute_modular_inverse(i - self.participant_id, q)) % q
            
        self.signing_state.w = w
        self.signing_state.big_w_by_id = big_w_by_id
        self.signing_state.k = gen_random_int(1, self.party_parameters.ec_n)
        self.signing_state.gamma = gen_random_int(1, self.party_parameters.ec_n)
        self.signing_state.gamma_elliptic = self.signing_state.gamma * self.party_parameters.ec_g

    def signing_part2(self) -> Signature:
        assert self.signing_state is not None
        assert self.participant_id in self.signing_state.signer_ids

        logger.debug(f'Partipant {self.participant_id}: signing part 2')

        encrypted_k = self.key_gen_state.paillier_public_key.encrypt(self.signing_state.k)

        for participant_id in range(1, self.party_parameters.party_size + 1):
            if participant_id not in self.signing_state.signer_ids or participant_id == self.participant_id:
                continue 

            # multiplication to addition share protocol 1 
            self.delegate.send(
                self.participant_id, 
                participant_id,
                MtoAP2P1(encrypted_k)
            )

            # multiplication to addition share protocol 2 
            self.delegate.send(
                self.participant_id, 
                participant_id,
                MtoAP2P2(encrypted_k)
            )

    def signing_part3(self):
        assert self.signing_state is not None
        assert self.participant_id in self.signing_state.signer_ids

        logger.debug(f'Partipant {self.participant_id}: signing part 3')

        # Compute little delta
        self.signing_state.delta_i = self.signing_state.k * self.signing_state.gamma

        alphas = self.signing_state.mToA_outputs_as_initiator_1.values()
        betas = self.signing_state.mToA_outputs_as_receiver_1.values()

        assert len(alphas) == len(betas)
        assert len(alphas) == (len(self.signing_state.signer_ids) - 1)

        self.signing_state.delta_i += sum(alphas) + sum(betas)
        self.signing_state.delta_i %= self.party_parameters.ec_n

        # Compute sigma 
        self.signing_state.sigma_i = self.signing_state.k * self.signing_state.w % self.party_parameters.ec_n

        mus = self.signing_state.mToA_outputs_as_initiator_2.values()
        nus = self.signing_state.mToA_outputs_as_receiver_2.values()

        assert len(mus) == len(nus) 
        assert len(mus) == (len(self.signing_state.signer_ids) - 1)

        self.signing_state.sigma_i += sum(mus) + sum(nus)
        self.signing_state.sigma_i %= self.party_parameters.ec_n

        self.delegate.broadcast(
            self.participant_id,
            SigningPostMtoABroadcast(
                delta_i=self.signing_state.delta_i, 
                gamma_elliptic=self.signing_state.gamma_elliptic
            )
        )

    def produce_signature(self, message: int):
        assert self.signing_state is not None
        assert self.participant_id in self.signing_state.signer_ids

        logger.debug(f'Partipant {self.participant_id}: completing signature round')

        assert self.signing_state.delta 
        assert self.signing_state.gamma_elliptic_summation is not None 

        delta_inv = compute_modular_inverse(self.signing_state.delta, self.party_parameters.ec_n)
        big_r: Point = delta_inv * self.signing_state.gamma_elliptic_summation
        self.signing_state.little_r = big_r.x.value

        s = (message * self.signing_state.k + self.signing_state.little_r * self.signing_state.sigma_i) % self.party_parameters.ec_n
        self.signing_state.s_by_id[self.participant_id] = s 
        self.delegate.broadcast(
            self.participant_id,
            SigningShare(s)
        )



        













