# myClick Cryptographic Protocol

**Status: DRAFT — in active design (2026-05-28). Nothing here is final.**

Sections 1–4 and the recovery half of section 9 are drafted as of 2026-05-28. Sections 5, 6, 7, 8, and 10 are still being designed and carry placeholders. Everything here is subject to change as the design firms up — this banner will be updated as sections lock.

This document specifies the cryptographic protocol behind myClick: how faces become encrypted embeddings, how members of a Click share the ability to recognise each other's children, how the server stays unable to decrypt anything sensitive, and how revocation works.

This protocol is being designed in the open. See the commit history for how it evolved.

## Table of Contents

1. [Threat model](#1-threat-model)
2. [Definitions and notation](#2-definitions-and-notation)
3. [Key hierarchy](#3-key-hierarchy)
4. [Enrolment (face to encrypted embedding)](#4-enrolment-face-to-encrypted-embedding)
5. [Embedding storage and the server's view](#5-embedding-storage-and-the-servers-view)
6. [Per-Click group key (the ratchet)](#6-per-click-group-key-the-ratchet)
7. [Recognition (on-device matching)](#7-recognition-on-device-matching)
8. [Revocation (key rotation; forward-immediate, forward-only)](#8-revocation-key-rotation-forward-immediate-forward-only)
9. [Key escrow and recovery](#9-key-escrow-and-recovery)
10. [Open questions](#10-open-questions)

---

## 1. Threat model

A threat model is two honest lists. The first is what the system must defend against — the attacks where, if we lose, the product has failed at its one job. The second is what the system concedes — the attacks we do not stop, stated plainly so nobody is misled about what "privacy-first" buys them.

The concessions matter as much as the defences. A privacy claim that quietly omits its limits is worse than no claim at all, because it invites the user to trust the system in exactly the situations where it cannot help. So we write both lists, and we write the second one carefully.

### 1.1 Who we defend against (must win)

These are the adversaries the architecture exists to beat. If any of these wins, that is a bug in the protocol, not an accepted risk.

- **myClick the company, or a malicious insider.** Even we cannot decrypt a child's biometric. This is the headline guarantee, and the entire architecture is built to make it true: the keys that decrypt embeddings live in users' Secure Enclaves and iCloud Keychains, never on our servers. An engineer with full production access, or a future owner of the company with bad intentions, still gets only ciphertext.
- **A server breach.** An attacker who steals the entire database — every row, every blob, every backup — gets only ciphertext. No plaintext embeddings, ever. There is no admin key, no "break glass" decrypt path, no master secret on the server that turns the stolen data into faces.
- **A subpoena or state actor.** We cannot hand over what we cannot decrypt. The honest answer to a warrant for a child's biometric is "here is the ciphertext we hold; we have no key for it." This is a deliberate design property, not a legal posture we adopt after the fact — the inability is structural.
- **A network eavesdropper.** Everything is TLS in transit and end-to-end encrypted at rest. An attacker watching the wire, or sitting on a compromised network path, sees encrypted bytes both in flight and as stored.
- **A malicious Click member.** A member of one Click cannot extract the embeddings of children in Clicks they are not in — group keys are scoped per Click and never shared across them. No member can obtain raw photos of anyone's children, because raw photos are never stored or transmitted; only non-reversible embedding vectors exist. And no member can recognise children outside the Click's premises or scope, because recognition is gated by the active scope at capture time.

### 1.2 What we concede (accepted risks, stated plainly)

These are the attacks we do not stop. We list them because pretending otherwise would be dishonest, and because knowing them lets a user decide what myClick is and is not good for.

- **A compromised device.** If the user's own iPhone is jailbroken, or running malware with sufficient privilege, the plaintext embeddings that are decrypted on-device for matching are exposed on that device. No end-to-end encrypted system can defend a compromised endpoint — the endpoint is where plaintext has to exist for the app to work at all. We protect data in transit and at rest, not against an attacker who already owns the phone.
- **Apple itself.** We rely on the Secure Enclave for key generation and on iCloud Keychain for escrow and recovery. If Apple is malicious, or is compromised at the hardware or operating-system level, the model breaks. We trust the platform — as does every iOS app, and as the user already does by carrying the device.
- **Authorised use.** A photographer with `can_capture` rights in a Click legitimately recognises the consented children of that Click. That is the product working as designed, not a breach. The crucial nuance, stated explicitly: **within a Click, members necessarily share the embeddings of opted-in children.** A photographer's device must hold the plaintext embeddings of the children they are allowed to recognise, or matching cannot happen at all. A determined malicious member could therefore extract those vectors from their own device. The protection here is not secrecy — it is **consent** (they were granted recognition rights to exactly these children, by those children's parents) plus **non-reversibility** (an embedding is a vector, not a photo; it cannot be turned back into an image of the child). If you grant someone the right to recognise your child, you are trusting them with that child's embedding. The protocol makes that trust explicit and scoped; it does not pretend to remove it.
- **Metadata.** The server cannot read embeddings, but it can see some metadata: who is a member of which Click, when embeddings are uploaded, and the shape of the Click membership graph. Content is encrypted; the social graph and timing are visible server-side. Full metadata-hiding — sealed-sender-style techniques that blind the server to who talks to whom — is a v2-and-later consideration, not a v1.0 promise.
- **Already-published photos.** Once an obscured photo is saved to the Photos library or posted somewhere, it is out of our control. Revocation is forward-only: it changes what future captures will obscure, but it cannot reach into a photo that already exists on someone else's phone or feed. We say this plainly in the product copy, and we say it here.

---

## 2. Definitions and notation

This section grounds the rest of the document. Terms defined here are used precisely throughout.

- **Account** — the principal. One human, one account, always. An account owns its holder's biometric (if they chose to enrol) and the biometrics of any dependents (children) they enrolled. Schools register accounts the same way an individual does.
- **Click** — the universal grouping primitive. A private circle of people who consent to recognise each other's children at specified places. A family is a Click; a class is a Click; a school's marketing-photo group is a Click. Same primitive at four members or four hundred.
- **Member** — an account's relationship to a Click. A member has three orthogonal attributes:
  - `is_biometrically_enrolled` — whether this person's own face is in the Click's recognition roster.
  - `can_capture` — whether this person may take photos under this Click (photographer rights). Granted two-sided: an admin proposes, the member explicitly accepts.
  - `is_admin` — whether this person has governance rights (invite, remove, configure premises, set the capturer ACL).
  All three are independent of one another.
- **Embedding** — a roughly 2048-byte face vector extracted on-device by MobileFaceNet. It is the only biometric artifact ever persisted, and it is always encrypted. An embedding is not reversible into a photograph.
- **Template set** — the small set of embeddings stored per enrolled person (more than one, to cover pose and expression variation). A detected face is considered a match if it clears the threshold against any template in the set. See section 4.
- **Premises** — a geographic scope attached to a Click, used to gate where recognition is active. A premises may be **permanent** (a polygon on a map, e.g. school grounds) or **event** (a bounded, time-limited scope for a one-off shoot). A Click may have zero, one, or many.
- **Capturer ACL** — the set of members with `can_capture = true` for a given Click. It defines whether capture is **symmetric** (every adult member may capture — family, class parent group) or **asymmetric** (admin plus admin-selected staff only — school marketing group).
- **Account identity key** — an ECC P-256 keypair generated in the Secure Enclave. Authenticates the account, wraps the account's vault key, and unwraps group keys delivered to this member. The private key is non-exportable.
- **Account vault key** — an AES-256 symmetric key that encrypts the account's own enrolled embeddings (the holder plus their children) at rest. It is the portable secret recovered on a new device.
- **Per-Click group key** — an AES-256 symmetric key, one per Click, rotated on every membership change. The embeddings opted into a Click are protected under this key so that all current members can decrypt them for recognition.

---

## 3. Key hierarchy

In plain English, there are three layers of keys, each doing one job.

The **first layer** is the account's identity. When you first launch myClick, the app asks the Secure Enclave — the dedicated security chip in your iPhone — to generate a keypair just for you. The private half of that keypair never leaves the chip. It cannot be exported, copied, or extracted, even by the app itself; the app can only ask the chip to use it. This identity key is how the server knows it is really you, and it is the key that wraps (encrypts) the next layer down.

The **second layer** is your vault key. This is the key that actually encrypts your own family's faces — your embeddings and your children's embeddings — when they sit at rest on disk and on our server. It is a symmetric key (the same key locks and unlocks), wrapped by your identity key so only your device can use it, and escrowed in iCloud Keychain so that if you lose your phone, you can get it back.

The **third layer** is the per-Click group key. Each Click has one. When a child is opted into a Click, that child's embedding is made decryptable by every current member of that Click — so the school photographer's phone can recognise the children whose parents opted them into the school Click, and nobody else's. The group key is how that sharing happens. It is handed to each member by wrapping it under that member's identity public key, so only that member's device can unwrap it. It rotates every time membership changes, which is what makes revocation work (see section 8).

A structural consequence worth stating directly: **a single child's embedding ends up encrypted in more than one form.** There is one copy encrypted under the parent's vault key — the parent's own private copy. And there is one copy (or one wrapped content-key) under each Click's group key that the child has been opted into. The same vector, sealed under different locks for different audiences.

### 3.1 The three layers, precisely

| Key | Type | Lives where | Wrapped / protected by | Job |
|-----|------|-------------|------------------------|-----|
| Account identity key | ECC P-256 keypair | Private key inside the Secure Enclave (non-exportable); public key published to the server | The Secure Enclave itself; never leaves the chip | Authenticates the account; wraps the vault key; unwraps group keys delivered to this member |
| Account vault key | AES-256 symmetric | On-device, and escrowed in iCloud Keychain | Wrapped by the account identity key; escrowed under iCloud Keychain | Encrypts the account's own enrolled embeddings (holder + children) at rest |
| Per-Click group key | AES-256 symmetric | On-device for each current member; distributed by the server in wrapped form | Wrapped under each member's identity public key for delivery | Makes a Click's opted-in embeddings decryptable by all current members for recognition; rotates on membership change |

### 3.2 Two decisions locked here

**Recovery is by iCloud Keychain escrow, not a user-held recovery phrase.** We escrow the account vault key in iCloud Keychain rather than asking the user to write down and safeguard a recovery phrase. The reasoning: it is by far the best consumer UX (a parent recovering a lost phone signs in with their Apple ID, as they already expect to); Apple is already a conceded trust anchor in our threat model (section 1.2), so escrow does not introduce a new party we were otherwise keeping out; and a lost recovery phrase would mean permanently lost family face data, with no path back. For a product whose users are ordinary parents, not crypto practitioners, the recovery-phrase failure mode is unacceptable.

**A group key with rotation on membership change, not a full double-ratchet.** A messaging protocol like Signal uses a double-ratchet to get per-message forward secrecy, because a chat is a continuous stream of messages and each one should be independently protected. A Click's embedding roster is not a message stream — it is a relatively static set that changes only when someone joins or leaves. Per-message forward secrecy would be overkill and would add messaging-grade complexity for no benefit. A per-Click group key that rotates on every membership change achieves exactly the guarantees we need — forward-immediate and forward-only revocation (section 8) — without that complexity.

---

## 4. Enrolment (face to encrypted embedding)

Enrolment is how a face becomes an encrypted embedding. It is the one moment where myClick handles a raw image of a child, so it is designed with the most care: the raw frames exist in memory only, for as long as it takes to extract embeddings, and are then zeroed.

### 4.1 The flow

1. **Initiate.** A parent starts enrolment, for themselves or for a child. (Enrolling a dependent is the common case.)
2. **Guided sweep.** The app guides a short multi-angle capture — turn left, turn right, look up, look down, smile. The frames are held in a memory buffer only. They are never written to disk.
3. **Quality gates.** As frames arrive, the app checks them:
   - A face must be detected.
   - Exactly one face must be present. Multiple faces is a **hard block** — enrolment will not proceed, because we must not accidentally enrol the wrong child.
   - Lighting must be adequate. Poor lighting is a **soft warning** — the app nudges the user but does not stop them.
   - Pose must vary across the sweep, so the template set actually covers a range of angles.
4. **Extraction.** MobileFaceNet runs on-device and extracts the embeddings from the captured frames. No image leaves the phone for this step; there is no cloud call.
5. **Zeroing.** The raw frames are zeroed from the memory buffer immediately, the moment extraction is done. See section 4.6.
6. **Encryption.** The embeddings are encrypted under the account's vault key.
7. **Storage.** The ciphertext is stored locally and synced to the server. The server receives ciphertext only — it never sees a frame, never sees a plaintext embedding.
8. **Consent read-back.** A consent read-back is recorded in the audit log: who enrolled whom, when, and under what consent statement.

### 4.2 Liveness: light, not hard-gated

The guided multi-angle sweep is itself a soft liveness check. A flat printed photo or a still image on a screen cannot easily produce a coherent multi-pose sweep — the geometry does not hold up across angles. Where TrueDepth hardware is available, we use it opportunistically to strengthen this.

We deliberately do **not** hard-block on liveness. Hard liveness gating would make enrolling a young child miserable — small children do not perform on cue, and a stuck enrolment flow is a recipe for a parent giving up. The real protection against enrolling a face that isn't a consenting person's is physical: you need physical access to the child to complete the sweep, and the sweep enforces that in practice. Liveness is a check we lean on lightly, not a wall.

### 4.3 Template set of 6 per person

We store a **template set of 6 embeddings** per enrolled person, not a single embedding:

1. Front, neutral
2. Front, smiling (expression variation)
3. Three-quarter left
4. Three-quarter right
5. Looking up
6. Looking down

A detected face matches the person if it clears the match threshold against **any one** of these templates.

The reason for more than one template is that a face embedding is sensitive along three axes at once: **yaw** (turning left/right), **pitch** (looking up/down), and **expression** (neutral vs smiling and beyond). Children's candid faces vary enormously across all three — a kid mid-laugh at a three-quarter angle looks very different to a neutral front shot. A single embedding would miss most real captures.

Four factors set the count:

1. **The pose-and-expression envelope to cover** — the range of angles and expressions a real candid photo will throw at us.
2. **Per-template pose tolerance** — each template reliably matches faces within roughly ±30 degrees of its own pose before confidence drops off. More templates, spaced across the envelope, keep every likely face within tolerance of some template.
3. **The false-accept asymmetry** — the dominant factor. See section 4.4.
4. **Compute and storage cost** — every detected face is compared against every template of every roster member, so the count multiplies the work done per frame and the bytes stored per person.

### 4.4 The false-accept asymmetry

This is the privacy-critical part of the calibration, and it is worth being precise about.

There are two ways matching can go wrong, and they are not equally bad:

- A **false-reject** — your own child is wrongly obscured — is annoying but safe. It fails closed: the worst outcome is that a photo you wanted has a blur where your kid's face is. No stranger is exposed. No privacy is breached.
- A **false-accept** — a stranger's child is shown unobscured because the system wrongly thought they were on the roster — is a privacy breach. It is the exact harm myClick exists to prevent.

These two failures are not symmetric, and the calibration is built around that. Adding templates raises the false-accept rate: each template is another chance for a stranger's face to clear the threshold, so the aggregate false-accept rate is roughly the per-template rate multiplied by the template count. So template count and match threshold are **co-tuned against a hard false-accept ceiling.** We deliberately spend the cost of more templates in the safe currency — false-rejects, over-obscuring — rather than the dangerous one.

**Starting ceiling: aggregate false-accept rate ≤ 0.1%** — a stranger wrongly recognised in fewer than 1 in 1000 faces — to be tightened if the closed-beta data on real children's faces allows.

What this spec fixes is the **method and the ceiling**, not a magic constant. The final template count (it could land anywhere from 5 to 7) and the match threshold are calibrated empirically during the closed beta against real children's faces. The principle — co-tune count and threshold against a hard false-accept ceiling, paying the cost in over-obscuring — is the durable decision.

### 4.5 Re-enrolment: periodic and explicit, age-banded, no silent learning

Children's faces change, so templates go stale. We refresh them by **periodic, explicit re-enrolment**, age-banded:

- Roughly every 3 months under age 5.
- Roughly every 6–12 months for older children.

The app reminds the parent; the parent redoes the sweep. That is the whole mechanism.

We deliberately do **not** silently update templates as recognition succeeds in the field. Continuous "learning" — quietly folding each successful match back into the template set — would mean continuously re-processing a child's biometric in the background. That is precisely the always-on biometric harvesting myClick exists to avoid. Explicit re-enrolment keeps the promise true: **we only process a child's face when you ask us to.** This is a deliberate accuracy cost, paid on purpose to keep the no-background-harvesting guarantee honest.

### 4.6 The zeroing guarantee

The raw enrolment frames are zeroed from the memory buffer **explicitly in code**, immediately after embeddings are extracted (step 5 above). This is documented here and visible in the open-source code: a reviewer can read the source and confirm that the frames are zeroed and that there is no disk write of the raw image.

We state the limit of that plainly. Source-level review proves the source does the right thing. **Binary-level verification — that the app actually shipped to the App Store does exactly this — awaits reproducible builds**, which we do not yet have. We will not imply more assurance than we can currently deliver. The source is auditable today; bit-for-bit verification of the shipped binary is future work.

---

## 5. Embedding storage and the server's view

In active design — not yet specified. See the project's design sessions.

## 6. Per-Click group key (the ratchet)

In active design — not yet specified. See the project's design sessions.

## 7. Recognition (on-device matching)

In active design — not yet specified. See the project's design sessions.

## 8. Revocation (key rotation; forward-immediate, forward-only)

In active design — not yet specified. See the project's design sessions.

## 9. Key escrow and recovery

The recovery half of this section is decided; the per-Click side is still in design.

Recovery is by **iCloud Keychain escrow of the account vault key** (the decision is recorded in [section 3.2](#32-two-decisions-locked-here)). The mechanics follow from the key hierarchy:

- The Secure Enclave identity key is device-specific and non-exportable — it never leaves the chip, so it is never the thing that gets recovered.
- On a new device, the app generates a **fresh identity key** in that device's Secure Enclave.
- The **portable secret — the account vault key — is recovered from iCloud Keychain**, re-established through the user's Apple ID plus device passcode, the standard iCloud Keychain recovery flow. With the vault key back, the account's own embeddings become decryptable again on the new device.
- Our server never sees the vault key at any point in this flow. Escrow is between the user and Apple; we are not in the path.

The harder part — **what happens to a Click if the sole admin's device is lost**, and how per-Click group keys are recovered or re-established in that case — is still in active design. See sections [6](#6-per-click-group-key-the-ratchet) and [8](#8-revocation-key-rotation-forward-immediate-forward-only), where the group-key lifecycle is being worked out.

## 10. Open questions

In active design — not yet specified. See the project's design sessions.
