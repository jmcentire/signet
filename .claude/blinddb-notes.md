# BlindDB Design Notes

Captured from conversation on 2026-02-27. These notes should also inform improvements to the standalone BlindDB repo.

## Core Insight: Information = Records + Relationships

Most people think of data protection as encrypting records. BlindDB's insight is that **relationships between records are often more valuable than the records themselves**.

- Knowing someone lives at "123 East West St" is useless — that's public knowledge.
- Knowing that *this specific person* lives there AND watched *these videos* AND has *this credit card* — that's the valuable information.
- BlindDB destroys these relationships by making them **generative**: the client constructs them via one-way deterministic cryptographic hashing, and the server literally cannot reconstruct them.

## Defense Layers (in order of importance)

1. **Relational opacity** (primary defense) — No user tables, no foreign keys, no joins. The server stores a flat pile of opaque record IDs and values. With millions of users, the server cannot determine which records belong to the same user.

2. **Signature-based tamper evidence** — Ed25519 signatures on data. Forging requires the private key. If I manipulate the payload, the signature doesn't match.

3. **Hash chains for provenance + ordering** — Each block includes the previous block's hash. Guarantees completeness and ordering. You can't remove or reorder entries.

4. **Encryption (defense-in-depth)** — AES-256-GCM for data with **independent value**. Credit card numbers work regardless of who they belong to. "Encrypt that shit." Not all data needs encryption — an address is public knowledge. But payment credentials, identity docs, etc. have value independent of relationships.

5. **Seed data (plausible deniability)** — Inject fake records (tunable ratio, e.g. 10% fake = 1/10 chance any record is noise). Shape fake data so "interesting" records correlate MORE strongly with fake data (inverse correlation design).

## Collision Handling

SHA-256 target space is large enough that collisions are essentially impossible. But even if there is a collision, you capture it:

```
hash(username + password) → user_id, salt                    // bootstrap
hash(username + user_id + 'videos watched') → {1,2,3,4,5,6} // index record
hash(username + password + salt + 'video 7') → COLLISION!    // rare
// Signal 2 steps upstream: change intermediary record
// Change index from 7 to 8
hash(username + user_id + 'videos watched') → {1,2,3,4,5,6,8}
hash(username + password + salt + 'video 8') → INSERT ok     // different hash
```

Key properties:
- The server doesn't know a collision happened — it just sees a different opaque ID on retry
- The index is an opaque counter, not semantically meaningful — bumping costs nothing
- In practice, use an indexed nonce for even more robustness
- The retry is entirely client-side; the server's interface is unchanged

## What Plain Text in the DB Means

Having "male" or "123 East West St" in the DB means nothing by itself. *Someone* lives there — that's true even if they never heard of the tool. We didn't disclose anything. The address exists in the world. The only information it carries is that it somehow got into the DB. The more prolific the service, the less obvious that pathway becomes.

## BlindDB Repo Improvements Needed

- Document the collision-detect-and-retry pattern explicitly
- Document the information theory argument (relationships > records)
- Document the seed data strategy (shaped random, inverse correlation)
- Document which data needs encryption (independent value) vs. which doesn't
- Add examples of the collection enumeration pattern with collision handling
- Add the "2 steps upstream" retry protocol
