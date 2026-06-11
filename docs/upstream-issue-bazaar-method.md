# Upstream issue draft #2 (x402-foundation/x402)

Verified LIVE against `main` @ `5304005` (2026-06-11). File at
https://github.com/x402-foundation/x402/issues — copy the body below.

---

**Title:** Reference FastAPI e2e server emits bazaar discovery extensions that fail the SDK's own validation (`'method' is a required property`) on every route

**Body:**

### Summary
Running the reference `e2e/servers/fastapi` server (current `main`) logs a
`UserWarning` for **every** protected route at request time:

```
x402: Route "GET /exact/evm/eip3009" has an invalid bazaar extension: input: 'method' is a required property
x402: Route "GET /exact/evm/permit2-eip2612GasSponsoring" has an invalid bazaar extension: input: 'method' is a required property
x402: Route "GET /upto/evm/permit2" has an invalid bazaar extension: input: 'method' is a required property
```

So the reference server, using the SDK's own discovery helper, produces bazaar
extensions that the SDK's own validator rejects.

### Root cause (as far as I can tell)
- `declare_discovery_extension`
  (`python/x402/extensions/bazaar/resource_service.py`) intentionally does **not**
  set `method`; its docstring says the method is "automatically inferred from the
  route key … or enriched by `bazaar_resource_server_extension` at runtime."
- The e2e server **does** register that enricher
  (`server.register_extension(bazaar_resource_server_extension)`,
  `e2e/servers/fastapi/main.py:106`).
- Yet the bazaar `info` JSON Schema requires `method`, and validation still
  reports it missing for every route — i.e. the enrichment does not populate
  `method` before validation runs (or runs too late).

### Reproduction
```bash
cd e2e/servers/fastapi
# any facilitator that answers GET /supported is enough
EVM_PAYEE_ADDRESS=0x209693Bc6afc0C5328bA36FaF03C514EF312287C \
FACILITATOR_URL=<facilitator> PORT=4055 python main.py
curl -s http://127.0.0.1:4055/exact/evm/eip3009   # triggers the warning per route
```

### Impact
- The canonical reference server ships with broken discovery metadata, so its
  resources would not be correctly indexable by a Bazaar.
- It also teaches integrators a non-working pattern: copying the e2e usage of
  `declare_discovery_extension` reproduces the warning.

### Suggested fix
Ensure `method` is injected (from the route key) into each discovery extension's
`info` **before** the bazaar `info`-vs-`schema` validation runs — or make
`declare_discovery_extension` accept/derive `method` so the produced extension
validates standalone.

### How it was found
Surfaced while building [x402-conformance](https://github.com/moped2110/x402-conformance),
a black-box conformance suite for x402 V2 endpoints.
