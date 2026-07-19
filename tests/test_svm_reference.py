"""Our exact verifier accepts the real x402 reference-client payload (K2-1 validation).

The transaction and requirements below are a genuine ``/verify`` request captured from
the Kora x402 demo facilitator's reference client on Solana devnet. If our Path-1
verifier accepts it (returns None), our §1/§2 implementation matches the reference
client's own payload — not merely our own builder. That is the strongest confirmation
of the SVM verify core, and it needs no devnet funding. Offline decode; skips without
the [svm] extra.
"""

from __future__ import annotations

import pytest

pytest.importorskip("solders")

from x402_conformance.svm_verify import verify_exact_svm_transaction

# Captured verbatim from the Kora x402 demo facilitator's /verify request body (devnet);
# on one line to rule out any base64 split error. Merchant == sponsor in this demo.
_REFERENCE_TX = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACzUYGig33fSQe7OUEFlUqj7B9XTsVvrp+/MU4AwBWSm+naXqfL01eMBof5p9Xor/j0X6r7zs9bfkhG57bJLaAFgAIBAweavefmL4jaEOSg1cmsWJSceXpodooXUJHvTO4ZOvIlVa/pD+AYoeQuE+2mC2h2scWjz49z3kyV+dflvKfgWpTqB5/cgFgj8fR8MYQ1ZxHnHgu9tZzp+JYTf5MyNq9OCJkOjoRiyCQWCYZY6n0l14H62tfRGNm7jzOlET93ln8N9ztELLORIVfxOpM9ATQoLQMrX/7NAaLb8bd5BgjfAC6nAwZGb+UhFzL/7K26csOb57yM5bvF9xJrLEObOkAAAAAG3fbh12Whk9nL4UbO63msHLSF7V9bN5E6jPWFfv8Aqe7LGDfxwJnxCI/dw58Y591icXymGNJpk9xOB9Di8c9ZAwUABQJkGQAABQAJAwEAAAAAAAAABgQCBAMBCgzoAwAAAAAAAAYA"  # noqa: E501
_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
_PAY_TO = "BR3jsXR6atrmt27e8HFWr5HfwCHUqkzxEqp6cxnngWgc"
_AMOUNT = 1000


def test_the_reference_client_payload_is_accepted() -> None:
    reason = verify_exact_svm_transaction(
        _REFERENCE_TX, mint=_MINT, pay_to=_PAY_TO, amount=_AMOUNT, fee_payer=_PAY_TO
    )
    assert reason is None, f"reference payload rejected as {reason!r}"
