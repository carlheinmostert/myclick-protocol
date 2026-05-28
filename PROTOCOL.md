# myClick Cryptographic Protocol

**Status: DRAFT — in active design (2026-05-28). Nothing here is final.**

All ten sections are drafted as of 2026-05-28. This is still a draft, not a final spec: the empirical calibration (template count, match threshold, false-accept ceiling, re-enrolment bands) is validated in the closed beta, and the v2 metadata-hiding items in section 10 remain open. Everything here is subject to change as the design firms up — this banner will be updated as sections lock.

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

This section is the precise enumeration of what the server can and cannot see. It is the technical backing for the public "what we store" page, and it is the place where the headline claim from [section 1.1](#11-who-we-defend-against-must-win) — "even we cannot decrypt a child's biometric" — gets made concrete. A privacy claim is only as good as the list behind it, so here is the whole list.

The discipline is simple: everything the server holds is either ciphertext (useless without keys the server does not have) or metadata we have already conceded ([section 1.2](#12-what-we-concede-accepted-risks-stated-plainly)). Nothing else.

### 5.1 What the server holds

All of this is either ciphertext the server cannot decrypt, or metadata we have openly conceded.

- **Encrypted embeddings.** The 2048-byte face vectors, as ciphertext. Never in plaintext.
- **Wrapped content-keys and wrapped group keys.** Each embedding is encrypted under its own content-key; that content-key is wrapped under the Click's group key; and each group key is wrapped under a member's identity public key. The server stores all of these wrapped forms and routes them to the right devices. It cannot unwrap any of them, because the unwrapping keys live in members' Secure Enclaves. (The content-key indirection is explained in [section 6](#6-per-click-group-key-the-ratchet).)
- **Account public keys.** Public by design — that is what "public key" means. The server uses them to verify accounts and to route wrapped group keys.
- **Membership metadata.** Which accounts are in which Click; each member's role flags (`is_biometrically_enrolled`, `can_capture`, `is_admin`); and the associated timestamps.
- **Premises definitions.** The geofence polygons attached to each Click.
- **The audit log.** Consent events and membership changes — who enrolled whom, who joined or left, when.

### 5.2 What the server never holds

This is the list that makes the "never on our servers" claim in [section 1.1](#11-who-we-defend-against-must-win) precise.

- **The account vault key.** It is escrowed in iCloud Keychain — that is, with Apple — and never on our servers. We are not in the escrow path at all (see [section 9](#9-key-escrow-and-recovery)).
- **Any group key in unwrapped form.** The server only ever sees group keys wrapped under members' identity public keys. It never holds one it could actually use.
- **Any plaintext embedding.** Decryption happens on-device, in memory, for the duration of a recognition session and no longer (see [section 7](#7-recognition-on-device-matching)).
- **Any raw photo or face image.** These are never uploaded — not at enrolment, not at capture, not at import. The server has never seen a child's face and never will.

### 5.3 What the server can therefore infer

We concede this metadata in [section 1.2](#12-what-we-concede-accepted-risks-stated-plainly); here is what it amounts to in practice.

- **The social and institutional graph.** From membership metadata, the server can see who is in which Clicks together — which accounts belong to a family, which parents are in a class, which staff are in a school group.
- **Timing.** When embeddings are uploaded, when members join or leave. The shape of activity over time is visible even though its content is not.
- **Premises locations.** The geofence polygons are server-stored in v1 (so they can sync to members' devices), so the server knows roughly where a Click operates — which school, which neighbourhood.

### 5.4 What the server cannot infer

- **Anyone's biometric.** Every embedding is ciphertext. The server cannot tell one child's face from another's, or reconstruct any face at all.
- **Whether a specific child was recognised in a specific photo.** Recognition happens entirely on-device, and the obscured output is never uploaded. The server has no idea who appeared in any photo, who was kept visible, or who was obscured.

### 5.5 Two decisions recorded here

**Premises are server-visible in v1.** The geofence polygons live on the server so they can sync to every member's device, which means the server can infer roughly where a Click operates. This sits inside the metadata concession already made in [section 1.2](#12-what-we-concede-accepted-risks-stated-plainly) — it is not a new concession, just the concrete form of one. Premises-encryption, which would hide locations from the server, is deferred to v2 along with the rest of metadata-hiding (see [section 10](#10-open-questions)).

**Storage substrate: Postgres `bytea` for embeddings.** Embedding ciphertext is small — roughly 12 KB per person for the six-template set — so it lives directly in Postgres as `bytea`. There is no efficiency reason to push it into object storage at this scale. Any larger encrypted artifacts that arise would use storage buckets configured with no server-side decrypt key, but at v1 there is nothing large enough to need them.

## 6. Per-Click group key (the ratchet)

This section consolidates the group-key decisions from [section 3](#3-key-hierarchy) and the sharing-mechanic design into one place. It is the mechanism that lets every current member of a Click recognise the children opted into it, and lets revocation work the moment membership changes.

### 6.1 One key per Click

Each Click has a single **AES-256 group key**. The embeddings opted into the Click are made decryptable under it (indirectly — see [section 6.3](#63-content-key-indirection)), so that every current member can recognise those children, and nobody outside the Click can.

### 6.2 Distribution rides on admin approval

When a new member is admitted, the admin's device wraps the current group key under the new member's identity public key and hands the wrapped key to the server to deliver. Only the new member's Secure Enclave can unwrap it.

This deliberately rides on the admin-approval step that already exists in the join flow. Admission to a Click already requires an admin to approve; wrapping the group key is folded into that same action. The rationale is accountability: a human admin is already in the loop deciding who gets in, so the cryptographic grant of recognition rights happens at exactly the moment a person took responsibility for admitting them — not automatically, not server-side.

### 6.3 Content-key indirection

Embeddings are not encrypted directly under the group key. Instead, **each embedding is encrypted under its own content-key, and the content-key is wrapped under the group key.** One extra layer of indirection.

The payoff is rotation cost. When membership changes and the group key must rotate ([section 6.4](#64-rotation-on-every-membership-change)), the only things that need re-wrapping are the content-keys — which are a handful of bytes each — not the embeddings themselves, which are kilobytes each. Rotating an 800-child school Click means re-wrapping 800 tiny content-keys, not re-encrypting 800 full embeddings. Same security, roughly a hundredfold less work. The indirection costs one cheap unwrap per embedding at read time and buys cheap rotation, which is the operation that actually happens often.

### 6.4 Rotation on every membership change

Every time membership changes — someone joins, someone leaves, someone is removed — the group key rotates:

1. A new group key is generated.
2. It is wrapped for each remaining member under that member's identity public key.
3. The content-keys are re-wrapped under the new group key.

After rotation, the old group key is dead: it decrypts nothing new, and anyone who only held the old key (a departed member) is locked out of everything uploaded thereafter. This is the engine of revocation ([section 8](#8-revocation-key-rotation-forward-immediate-forward-only)).

### 6.5 Multiple admins, and serialising concurrent rotations

Any admin can distribute or rotate the group key. This is native to the model rather than a special case: every admin is a member and therefore already holds the group key, and `is_admin` is just a per-member attribute. There is no separate "key-holder" role to manage.

That raises one concurrency hazard: two admins rotating at the same moment could produce two conflicting "new" group keys, leaving members in an inconsistent state. We prevent this by **serialising rotations with a version stamp** on the server (optimistic concurrency). A rotation references the key version it intends to replace. If two rotations race, the first to land wins; the second is rejected because the version it referenced is now stale, and it retries against the new version. The server never has to understand the key material to do this — it only compares version numbers — so serialising rotations does not require the server to hold anything it should not.

Multiple admins is also the institutional recovery-resilience mechanism (see [section 9](#9-key-escrow-and-recovery)).

### 6.6 Why group-key-plus-rotation, not a full double-ratchet

This decision is recorded in [section 3.2](#32-two-decisions-locked-here) and restated here for completeness, because it is the defining choice of this section. A messaging protocol uses a double-ratchet to give every message its own forward secrecy, because a chat is a continuous stream and each message should be independently protected. A Click's embedding roster is not a stream — it is a relatively static set that changes only on membership or opt-in changes. Per-message forward secrecy would be solving a problem we do not have, at messaging-grade complexity. Group-key-plus-rotation delivers exactly the guarantees we need — forward-immediate and forward-only revocation ([section 8](#8-revocation-key-rotation-forward-immediate-forward-only)) — and nothing we do not.

## 7. Recognition (on-device matching)

Recognition is the moment the product earns its name: faces are detected, matched against the people you are allowed to recognise, and everyone else is obscured. All of it happens on the device. No face, no embedding, and no recognition result ever leaves the phone.

### 7.1 The flow

1. **Detect.** Vision detects faces in the frame and returns their bounding boxes.
2. **Extract.** MobileFaceNet extracts an embedding for each detected face, in memory.
3. **Compare.** The device compares each face's embedding against the **active roster** — the union of the photographer's `can_capture` Clicks that are active at the current location in Mode A, or the explicitly-selected Click's roster in Mode B.
4. **Decide.** A match above threshold against **any one** of a person's six templates keeps that face visible. No match obscures it.
5. **Zero.** Every detected face's embedding is zeroed the moment its decision is made.

### 7.2 The unconsented-face invariant (R2)

This is a hard guarantee, and it is the legal hook (POPIA legitimate-interest, GDPR equivalent) that makes processing strangers' faces defensible at all: **we never build a database of children we do not have consent to remember.**

A stranger's embedding is computed in memory, used only for the single obscure-or-keep comparison, and zeroed within milliseconds. It never touches disk. It never touches the network. It is never stored, indexed, or retained in any form. The only thing that persists from a stranger's face is the obscuring that protected them.

### 7.3 Roster decryption lifecycle (R1)

The active roster is stored as ciphertext (that is the whole point of [sections 5](#5-embedding-storage-and-the-servers-view) and [6](#6-per-click-group-key-the-ratchet)). Recognition needs it in plaintext. So the roster is decrypted into memory at the start of a session, held for the session, and zeroed at the end.

No plaintext roster is ever written to disk. Only the **encrypted** roster is cached on disk for fast loading; decryption is always in-memory and per-session. This is what keeps the encrypted-at-rest guarantee true for consented children, not only for strangers — your own child's embedding is no more exposed at rest than anyone else's.

### 7.4 What an active recognition session is

A recognition session is precisely the period during which the device holds a decrypted roster in memory. Its boundaries are defined exactly, because the roster's lifetime is a security property.

- **Starts** when recognition is needed: the camera viewfinder becomes active (Mode A), or an import batch begins (Mode B).
- **Ends — hard boundaries, roster zeroed immediately, no exceptions:**
  - the app backgrounds, or the Face ID app-lock engages;
  - the app terminates;
  - the camera screen closes, or the Mode B batch finishes or is cancelled.
- **Soft boundary (foreground only):** if the user briefly navigates away from the camera while the app is still foregrounded and unlocked, the roster is held for roughly 60 seconds — so flipping quickly back to the camera does not pay the decryption cost again — and then zeroed. Any background or lock during that window zeroes it immediately. The soft boundary never survives leaving the app.
- **Recomposes within a session:** in Mode A, as the device crosses premises boundaries, Clicks drop out of the in-memory roster (their portion zeroed) or join it (their portion decrypted). The session persists; its roster contents track the active scope.

### 7.5 Lock-screen camera flow

The camera and recognition are reachable from the lock screen **without** a Face ID prompt, the way Apple Camera is. The Face ID app-lock gates only the management surfaces — the Clicks list, settings, the licence inventory, the audit log — never the camera.

The security reasoning follows directly from the threat model. We already concede the stolen or compromised device ([section 1.2](#12-what-we-concede-accepted-risks-stated-plainly)). The camera only ever obscures faces; it never exposes the roster, the embeddings, or the social graph to whoever is holding the phone. So a thief who grabs the phone gets a camera that will recognise the owner's family if those people happen to be physically standing in front of it — and nothing else. They cannot browse Clicks, see who is enrolled, read settings, or open the audit log. The decrypted roster is still zeroed the instant the app backgrounds or locks; it is simply re-decrypted on each quick launch. We trade nothing of value for the convenience of a grab-and-shoot camera.

### 7.6 Progressive roster loading

Rosters load smallest-and-likeliest first. The family Click — a handful of people — decrypts in single-digit milliseconds; most-recently-used Clicks come next; large rosters fill in over tens of milliseconds. Crucially, this decryption overlaps camera-hardware initialisation, which takes roughly 200–400 ms on every launch regardless, so the roster work is hidden behind a wait that was happening anyway and is invisible to the user.

Combined with two other rules, the quick grab from the lock screen feels instant:

- **Shutter-independence:** the shutter captures the frame instantly; obscuring is applied when the decision is ready, not before. You never wait to take the shot.
- **Fail-closed:** until the decision is ready, faces are obscured.

The only observable artifact is benign: a school-opted-in child who is not part of the owner's family might be briefly over-obscured — for the tens of milliseconds until the school roster finishes loading — and over-obscuring is always the safe direction to fail.

### 7.7 Matching performance (R3)

Matching is brute-force vectorised cosine similarity: one face's embedding is compared against the whole roster matrix in a single operation, using Accelerate/BNNS. This is more than fast enough for v1 scale, which runs to thousands of templates. Approximate-nearest-neighbour indexing is deferred until a single roster exceeds roughly 10,000 templates — a threshold a v1 Click does not reach.

### 7.8 Mode B

Mode B uses the same recognition engine described above, with one difference: the roster is the **explicitly-selected Click's** roster rather than the capture-by-union of active Clicks. The user chooses the Click context at import time (because imported photos were not taken under any photographer's identity in myClick), and from there detection, extraction, comparison, decision, and zeroing are identical.

## 8. Revocation (key rotation; forward-immediate, forward-only)

Revocation is what happens when someone leaves a Click or is removed from it. The honest version of revocation has a sharp limit, and we state it here as plainly as we do everywhere else.

### 8.1 The mechanism is key rotation

On any membership change — a member removed, or a member leaving — the group key is rotated exactly as described in [section 6.4](#64-rotation-on-every-membership-change): a new group key is generated, wrapped for each remaining member under their identity public key, and the content-keys are re-wrapped under the new key. The departed member never receives the new key, so everything uploaded after the rotation is sealed against them.

### 8.2 Forward-immediate

Once a rotation propagates — a matter of seconds — every capturer's future photos respect the new key. A removed member can no longer decrypt any newly uploaded embedding. The window between the membership change and full effect is the propagation time, measured in seconds, not the indefinite lag of waiting for some manual cleanup.

### 8.3 Forward-only (stated plainly)

Revocation cannot reach backwards. Photos already taken and saved to other members' devices, or already published somewhere, **cannot be retroactively obscured.** We have no way to reach into anyone else's photo library or anyone else's feed. The product copy says this directly — *"Revocation applies to future photos"* — and so does this spec. A privacy promise that implied otherwise would be a lie, and the limit is structural: a photo that already exists on another person's phone is simply out of reach.

### 8.4 Best-effort device wipe (stated honestly)

On revocation, the server also sends a wipe signal. A cooperating client receiving it deletes its cached encrypted roster for that Click. We are honest about what this is and is not worth: a **malicious** client can simply ignore the signal, and we cannot force it. So the wipe is best-effort cleanup, not a guarantee.

The real guarantee is the key rotation in [section 8.1](#81-the-mechanism-is-key-rotation) — the departed member cannot decrypt anything uploaded after they left, whether or not their client honoured the wipe. We do not imply the wipe is airtight, because it is not. It is a courtesy that tidies up cooperating devices; the cryptography is what actually protects you.

### 8.5 Account close

On account close, data is **soft-deleted for 30 days** and then hard-deleted. The grace window allows recovery from an accidental or coerced closure; after it, the data is gone. A right-of-access JSON export of an account's own data is available on request, so a user can take their data with them.



## 9. Key escrow and recovery

Recovery is the unglamorous part of any encryption design, and the part that decides whether real people can trust it. A parent who loses their phone must be able to get their family's face data back — and must be able to keep participating in the Clicks they were in — without us holding a key that breaks the whole model. This section is how.

### 9.1 What recovery restores

Recovery is by **iCloud Keychain escrow** (the decision is recorded in [section 3.2](#32-two-decisions-locked-here)), and it escrows two things: the **account vault key** and the **material needed to rejoin the account's Clicks**. The second part matters as much as the first — account recovery restores full Click participation, not just the private vault. A recovered parent gets back their own embeddings and is able to take part in the school Click, the class Click, and the family again, rather than being left holding their own data but locked out of everyone else's.

### 9.2 The mechanics

The mechanics follow from the key hierarchy:

- The Secure Enclave identity key is device-specific and non-exportable — it never leaves the chip, so it is never the thing that gets recovered.
- On a new device, the app generates a **fresh identity key** in that device's Secure Enclave.
- The **portable secrets — the account vault key plus the group-key-unwrapping material — are recovered from iCloud Keychain**, re-established through the user's Apple ID plus device passcode, the standard iCloud Keychain recovery flow. With these back, the account's own embeddings become decryptable again and its Click memberships can be re-established on the new device.
- Our server never sees the vault key at any point in this flow. Escrow is between the user and Apple; we are not in the path.

### 9.3 Institutional recovery resilience: multiple admins

For Clicks — and especially institutional ones — the multiple-admin model ([section 6.5](#65-multiple-admins-and-serialising-concurrent-rotations)) is also the recovery story. A Click is not bricked if one admin's device **and** iCloud are both lost, because any other admin can still rotate the group key and admit members. The Click keeps functioning through the surviving admins.

For institutional Clicks such as schools, multiple admins is therefore **strongly recommended**, not optional in spirit — a school running its photography on one person's phone is one lost device away from a stuck Click.

### 9.4 The remaining open case

The one case not yet fully designed is the rare worst case: **all** admins of a Click simultaneously losing access. Multiple admins mitigates this — the more admins, the less likely — but it does not formally close it. The complete recovery design for the all-admins-lost case is noted as open work in [section 10](#10-open-questions).

## 10. Open questions

These are the things we have deliberately deferred or not yet pinned down. We list them here for the same reason we list the conceded threats in [section 1.2](#12-what-we-concede-accepted-risks-stated-plainly): an auditor should be able to see the edges of what is designed, not just the middle.

**Deferred to v2**

- **Metadata-hiding.** Sealed-sender-style protection that would blind the server to the social graph and to timing. In v1 the server can infer who is in which Clicks together and when activity happens ([section 5.3](#53-what-the-server-can-therefore-infer)). Closing that is a v2 goal.
- **Premises-encryption.** Hiding premises locations from the server. In v1 the geofence polygons are server-stored so they can sync to devices, so the server knows roughly where a Click operates ([section 5.5](#55-two-decisions-recorded-here)). This is deferred to v2 alongside the rest of metadata-hiding.

**Empirical calibration (closed beta)**

- **Final template count, match threshold, and false-accept ceiling.** The method and the starting ceiling (≤ 0.1% aggregate false-accept) are fixed in [section 4.4](#44-the-false-accept-asymmetry); the final template count (somewhere between 5 and 7) and the threshold are calibrated on real children's faces across varied lighting and devices during the closed beta, and the ceiling confirmed there.
- **Re-enrolment band tuning.** The age-banded re-enrolment schedule ([section 4.5](#45-re-enrolment-periodic-and-explicit-age-banded-no-silent-learning)) is a starting estimate. We will measure staleness-driven false-rejects — especially for under-5s on the 3-month band — so the bands are grounded in data rather than guessed.

**Verifiability roadmap**

- **Reproducible builds.** So that users can verify the binary shipped to the App Store matches the public source. This closes the design-versus-deployment gap noted throughout (for example in [section 4.6](#46-the-zeroing-guarantee)). Roadmap item.
- **Server attestation / transparency.** So that users can verify the deployed server actually runs the published E2EE module, not a modified one. Roadmap item.

**Still in design**

- **Full group-key recovery if all admins of a Click lose access.** Multiple admins ([section 9.3](#93-institutional-recovery-resilience-multiple-admins)) mitigates this; the complete recovery design for the all-admins-lost case is not yet specified.
- **The spec's canonical format.** Whether this stays GitHub-rendered markdown, becomes a Signal-style PDF, or takes an RFC shape. For now, the canonical form is this markdown document.
