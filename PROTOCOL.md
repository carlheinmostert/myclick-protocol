# myClick Cryptographic Protocol

**Status: DRAFT — in active design (2026-05-28). Nothing here is final.**

This document specifies the cryptographic protocol behind myClick: how faces become encrypted embeddings, how members of a Click share the ability to recognise each other's children, how the server stays unable to decrypt anything sensitive, and how revocation works.

## Table of Contents

To be filled in as the design firms up. Planned sections:

1. Threat model
2. Definitions and notation
3. Key hierarchy
4. Enrolment (face to encrypted embedding)
5. Embedding storage and the server's view
6. Per-Click group key (the ratchet)
7. Recognition (on-device matching)
8. Revocation (key rotation; forward-immediate, forward-only)
9. Key escrow and recovery
10. Open questions

---

This protocol is being designed in the open. See the commit history for how it evolved.
