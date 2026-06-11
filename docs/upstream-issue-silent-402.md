# Upstream issue draft (x402-foundation/x402)

Verified against `main` @ `5304005` (2026-06-11). File at
https://github.com/x402-foundation/x402/issues — copy the body below.

---

**Title:** FastAPI payment middleware silently swallows unexpected exceptions as an empty-body 402 (no logging)

**Body:**

### Summary
The FastAPI payment middleware catches any unexpected exception on the
settlement path and returns an empty-body **HTTP 402 Payment Required** with no
logging. An internal server error (RPC failure, DB error, a bug) is therefore
indistinguishable, to both clients and operators, from a normal "payment
required" response.

### Location
`python/x402/http/middleware/fastapi.py` — the final catch-all in the
`payment-verified` branch:

```python
            except FacilitatorResponseError as error:
                return _facilitator_error_response(error)
            except Exception:
                return JSONResponse(content={}, status_code=402)
```

The module imports/uses **no logging** at all (`grep -c "logg" returns 0`).

### Why it matters
- **Misleading status.** Per the core spec (§4 Response Types), an internal
  failure should map to **Server Error → 500**, not `402 Payment Required`.
  Returning 402 tells a paying client/agent "you still need to pay" when the
  server actually crashed — an autonomous agent may retry and pay again into a
  broken endpoint.
- **Zero observability.** With no log line, an operator has no signal that an
  exception occurred; the failure is completely silent.

### Reproduction
Cause any exception in the post-verification settlement path (e.g. the
facilitator becomes unreachable mid-settle, or the resource handler raises after
verification). The client receives `402` with an empty JSON body `{}` and the
server logs nothing.

### Suggested fix
1. Log the exception (`logger.exception(...)`) so failures are diagnosable.
2. Return `500` (Server Error) for unexpected exceptions, reserving `402` for
   genuine payment-required / payment-failed cases. Optionally include a minimal
   error body distinguishable from a payment response.

### How it was found
Surfaced while building [x402-conformance](https://github.com/moped2110/x402-conformance),
a black-box conformance suite for x402 V2 endpoints.
