# myClick Protocol

The cryptographic protocol behind myClick — a privacy-first iOS camera that keeps consented faces visible and obscures everyone else, with end-to-end-encrypted biometrics.

This repository is public from day one and develops in the open. It holds the protocol specification and, over time, a reference implementation of the cryptographic module. Public scrutiny is myClick's trust mechanism: we'd rather you read and challenge the design than take our word for the privacy claims.

## What's here

- `PROTOCOL.md` — the protocol specification (in active design; draft)
- Reference implementation — to come

## Status

Early. The protocol is being designed in the open. Expect the spec to change as the design firms up. Nothing here is final until v1.0 of the spec is tagged.

## Privacy posture (what the protocol guarantees)

- On-device face matching; raw images never reach the server
- Embeddings only, never raw images; stored as encrypted vectors
- No persistent biometric for unconsented faces
- End-to-end encrypted: the company holding the servers cannot decrypt anything sensitive

## License

Mozilla Public License 2.0 (see LICENSE). MPL is copyleft-lite: modifications to these privacy-critical files must themselves be published, keeping any fork honest about what it changed.

## Security

See SECURITY.md. Disclose responsibly to security@myclick.camera.

## Contributing

See CONTRIBUTING.md. myClick is open for audit, not code contributions, during v1.0.
