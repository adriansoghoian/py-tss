import unittest
from typing import List
from pytss.gg20 import (
    Participant,
    Parameters,
    CommunicationDelegate,
    BaseMessage
)
from pytss.elliptic_curve import (
    secp256k1,
    secp256k1_generator,
    secp256k1_order,
    PrivateKey,
    Signature,
    Point
)
from pytss.common_crypto import (
    gen_random_int
)
from pytss.secret_sharing import (
    recover_secret
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


class TestGG20(unittest.TestCase):

    def _test_signature(self, public_key: Point, private_key: int, security_parameter: int = 256):
        N = secp256k1_order
        G = secp256k1_generator

        private_key = PrivateKey(private_key, G, N)
        z = gen_random_int(0, 2 ** security_parameter) # random message 
        signature: Signature = private_key.sign(z)
        self.assertTrue(signature.verify(z, public_key))

    def test_e2e(self):
        params = Parameters(
            security_parameter=256,
            paillier_security_parameter=2048,
            party_size=4,
            threshold=3,
            ec=secp256k1,
            ec_g=secp256k1_generator,
            ec_n=secp256k1_order
        )
        print(f'Initiating MPC key generation across a ({params.threshold}, {params.party_size}) threshold party\n')

        participants: List[Participant] = []
        test_delegate = TestDelegate()
        for i in range(1, params.party_size + 1):   
            participants.append(
                Participant(
                    delegate=test_delegate,
                    party_parameters=params,
                    participant_id=i
                )
            )
        test_delegate.participants = participants

        ## KEY GEN ## 
        for each in participants:
            each.key_gen()

        # public key is sum of all yi's
        public_key = Point(x=None, y=None, curve=params.ec) 
        for each in participants:
            public_key += each.key_gen_state.y

        # Check that participants can assemble their own pub keys 
        for each in participants:
            self.assertEqual(public_key, each.public_key())

        # Test out private key, which is a sum of individual shares 
        private_key_1 = sum([ each.key_gen_state.secret_key_share for each in participants ])
        self._test_signature(public_key, private_key_1)

        print(f'Generated shared ECDSA public key with parameters: {public_key}\n')

        ## Check shamir shares 
        for each in participants:
            self.assertEqual(len(each.key_gen_state.secret_key_shamir_shares), params.party_size)

        ## Check that shamir shares can reconstruct the secret value
        # Take first participant as primary, and reconstruct 
        # its secret using shares sent to the other 2 participants
        primary_id = participants[0].participant_id
        secret_value = participants[0].key_gen_state.secret_key_share
        ss_2 = 2, participants[1].key_gen_state.other_shamir_shares_by_id[primary_id]
        ss_3 = 3, participants[2].key_gen_state.other_shamir_shares_by_id[primary_id]
        ss_4 = 4, participants[3].key_gen_state.other_shamir_shares_by_id[primary_id]

        recovered_secret = recover_secret([ss_2, ss_3, ss_4], params.ec_n)
        self.assertEqual(secret_value, recovered_secret)

        ### Check that the x_i values are a (t, n) Shamir sharing of the collective private key 
        # aka sum of all individual shares 
        known_private_key = sum([each.key_gen_state.secret_key_share for each in participants])

        primary_id = participants[0].participant_id
        ss_2 = 2, participants[1].key_gen_state.x
        ss_3 = 3, participants[2].key_gen_state.x
        ss_4 = 4, participants[3].key_gen_state.x

        recovered_private_key = recover_secret([ss_2, ss_3, ss_4], params.ec_n)
        self.assertEqual(recovered_private_key, known_private_key % params.ec_n)

        ## SIGNING ## 
        chosen_participant_ids = [1, 2, 3]
        message = gen_random_int(0, 2 ** params.security_parameter)
        print(f'Initiating MPC signing across {params.threshold} participants of {params.party_size} total\n')

        signing_participants: List[Participant] = [ each for each in participants if each.participant_id in chosen_participant_ids ]
        for each in signing_participants:
            each.prepare_for_signing(message, set(chosen_participant_ids))
        
        for each in signing_participants:
            each.sign()

        ## Check that the additive share stuff work
        private_key_2 = sum([each.signing_state.w for each in participants if each.participant_id in chosen_participant_ids])
        self._test_signature(public_key, private_key_2)
        
        # Check that the first mToA protocol worked...
        participant_1 = participants[0]
        participant_2 = participants[1]
        
        original_a = participant_1.signing_state.k
        original_b = participant_2.signing_state.gamma

        x = (original_a * original_b) % params.ec_n

        new_a = participant_1.signing_state.mToA_outputs_as_initiator_1[2]
        new_b = participant_2.signing_state.mToA_outputs_as_receiver_1[1]
        new_x = (new_a + new_b) % params.ec_n

        self.assertEqual(new_x, x)

        # It worked...now check the second mToA protocol
        participant_1 = participants[0]
        participant_2 = participants[1]
        
        original_a = participant_1.signing_state.k
        original_b = participant_2.signing_state.w # key diff

        x = (original_a * original_b) % params.ec_n

        new_a = participant_1.signing_state.mToA_outputs_as_initiator_2[2]
        new_b = participant_2.signing_state.mToA_outputs_as_receiver_2[1]
        new_x = (new_a + new_b) % params.ec_n

        self.assertEqual(new_x, x)

        # Check that each party broadcast delta_i, and computed sum(delta_i)
        # correctly
        delta = None 
        for each in signing_participants:
            print(each.participant_id)
            print(each.signing_state)
            print(each.signing_state.delta_by_id)
            self.assertTrue(each.signing_state.delta)
            if delta is None:
                delta = each.signing_state.delta
            else:
                self.assertEqual(delta, each.signing_state.delta) 

        # delta should equal sum(k_i) * sum(gamma_i)
        sum_k_i = sum([ each.signing_state.k for each in signing_participants ]) % params.ec_n
        sum_gamma_i = sum([ each.signing_state.gamma for each in signing_participants ]) % params.ec_n
        
        self.assertEqual(delta % params.ec_n, (sum_k_i * sum_gamma_i) % params.ec_n)

        # Now check the actual signature
        sigs: List[Signature] = [ each.signature() for each in signing_participants ]
        print(f'Sample signature: {sigs[0]}\n')

        for each in sigs:
            self.assertTrue(each.verify(message, public_key))
            print("Verified signature")




