from __future__ import annotations

from dade_app import DecisionCode, UseDecision


VICE_DECISION_CODES: dict[DecisionCode, int] = {
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


def vice_decision_code(decision: UseDecision) -> int:
    return VICE_DECISION_CODES[decision.code]
