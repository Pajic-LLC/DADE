import unittest

from dade_app import DecisionCode, UseDecision
from dade_vice import VICE_DECISION_CODES, vice_decision_code


EXPECTED = {
    DecisionCode.OWNED: 0,
    DecisionCode.NOT_OWNED: 1,
    DecisionCode.WRONG_ASSET: 2,
    DecisionCode.INVALID_DEED: 3,
    DecisionCode.UNTRUSTED_ISSUER: 4,
    DecisionCode.OWNER_PROOF_FAILED: 5,
    DecisionCode.DEVICE_NOT_AUTHORIZED: 6,
    DecisionCode.DEVICE_PROOF_FAILED: 7,
    DecisionCode.CONTROLLER_REVOKED: 8,
    DecisionCode.ISSUER_KEY_REVOKED: 9,
    DecisionCode.TRUST_STATE_ROLLBACK: 10,
    DecisionCode.RIGHT_NOT_GRANTED: 11,
}


class ViceProviderContractTests(unittest.TestCase):
    def test_all_application_decisions_have_stable_vice_codes(self) -> None:
        self.assertEqual(VICE_DECISION_CODES, EXPECTED)
        self.assertEqual(set(VICE_DECISION_CODES), set(DecisionCode))

    def test_owned_maps_to_zero(self) -> None:
        decision = UseDecision(
            allowed=True,
            code=DecisionCode.OWNED,
            asset_id="com.pajic.vice",
            detail="local ownership proof is valid",
        )
        self.assertEqual(vice_decision_code(decision), 0)


if __name__ == "__main__":
    unittest.main()
