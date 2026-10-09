# Review revisions, 2026-10-09

The editable source is `draft-uri-cfrg-pquake.md`. These notes record the
response to the supplied email chain and the questions still requiring
author input or cryptographic review.

## Guilin Wang

- Added the problem statement, design rationale, and related-work discussion
  in the Introduction. Comparators include MQV/HMQV, KEMTLS, KEMTLS-PDK,
  Muckle#, and CKAKE; their proofs are not attributed to PQuAKE.
- Replaced the unconditional "Formal Proofs" claims with "Security Analysis
  and Formal Evidence." Explained the contribution of the ephemeral secret,
  both static KEM secrets, transcript ordering, and directional confirmation
  keys. Distinguished a security argument from a verified claim about a
  particular model or wire specification.
- Combined the three protocol-integration sections into "Initial
  Considerations for Protocol Integration." Removed proposed message
  replacements and assertions that an EDHOC mapping preserves compactness.
- Expanded safe-use requirements for credential validation, authorization,
  randomness, secret erasure, input validation, and failure handling.

## Nick Sullivan and John Preuß Mattsson

- Stated the intended Informational reference/building-block objective,
  proposed constrained-link use case, and criteria for a fair comparison.
- Distinguished related KEM-authentication work from explicit demand for
  PQuAKE. No requesting working group or deployment evidence was supplied
  in the email chain; the draft says no such request is documented here.
- Cited the CFRG process and left the publication stream open. The edit
  does not change the individual draft's submission metadata or imply
  adoption, consensus, or endorsement.
- Removed language presenting PQuAKE as guidance for TLS or LAKE. Each
  integration retains responsibility for its design and security analysis.

## Specification corrections and review issues

- Aligned prose with the original diagram's static encapsulation directions:
  the initiator creates `ct_i, ss_i` for `pk_r`; the responder creates
  `ct_r, ss_r` for `pk_i`. Standardized decapsulation notation as `(sk, ct)`.
- Aligned logical KDF and transcript definitions with CAKE-HI Figure 1:
  `ss_pre` contributes to both KDFs (empty if unused); the transcript uses
  chained hashes; initiator confirmation covers `H_i || H_r` and responder
  confirmation covers `H_r || H_i`, with separate keys. The original draft
  omitted `ss_pre` from the final KDF and disagreed internally on
  confirmation inputs. The corrected construction still needs comparison
  with the versioned formal artifacts.
- Flagged the unspecified AES-GCM nonce allocation across both senders,
  exact HKDF invocations, transcript encoding, certificate profile,
  session/transport association, and identity-sensitive failure behavior.
  These need cryptographic review; this edit does not invent a completed
  profile or claim that the changes have been formally verified.
- Distinguished credential encryption from whole-exchange anonymity.
  Cited the Kyber anonymity research invoked by the paper, and left the
  exact mapping to standardized ML-KEM-1024 for review. IND-CCA2 and implicit
  rejection alone are not sufficient evidence for this privacy claim.
- Preserved the paper's rule delaying an out-of-band expected-identity
  decision until after confirmation, while retaining the cryptographic
  input and credential-validity checks needed before encapsulation.
- Summarized the computational and symbolic security definitions and their
  limits: pre-authenticated key setup, credentials modeled as public keys,
  restricted forward-secrecy exposure experiments, and different identity
  and authentication queries. Full X.509 identity agreement and a QROM
  proof are not established by these abstractions.
- Identified a rationale gap in the paper: its SHA-3 sponge citation does
  not justify SHA-384 collision resistance. A quantum-security result for
  HMAC also does not by itself instantiate the final KDF's random oracle.
- Updated X.509 to RFC 5280, added RFC 5869 for HKDF, corrected the
  KEMTLS-PDK title, MQV publication date, and Muckle# author name, and
  updated NIST SP 800-227 to its final publication. Removed uncited
  bibliography entries.

## Evidence and remaining author input

The author supplied the complete 14-page CAKE-HI paper corresponding to
[IACR ePrint 2026/1749](https://eprint.iacr.org/2026/1749). Sections 3-6,
Figure 1, Section 7, Section 8, and the appendix comparison tables were
reviewed, with visual inspection of the diagram and tables. The revision
now identifies reported results by their definitions and experiments,
rather than relying on the abstract alone.

The author indicated that full proof references will be available after
the weekend. Versioned scripts, models, tool versions, and independent
reproduction remain pending. Reading the paper is not a reproduction of
its mechanized proofs.

The applicability discussion now includes Appendix Table 4's handshake
counts and Table 3's operation-count trade-off. The table totals imply
reductions relative to mTLS of 30.7% (Dilithium5 row) and 40.2%
(FALCON1024 row). The prose's 44.2% figure uses the smaller CAKE-HI total
as denominator and must not be repeated as a reduction relative to mTLS.
The paper uses Kyber/Dilithium-era algorithms and estimated certificates;
it does not measure this draft's ML-KEM/ML-DSA wire encoding, device
energy, or integrated-protocol latency. Section 8 identifies empirical
integrated-protocol measurements as future work.

Further input is needed for specific deployment requirements or explicit
working-group requests. The paper supplies candidate use cases and a
comparison, but does not establish such a request for PQuAKE.

## Validation

The final `make latest lint` build passed with the existing local toolchain
and a bibliography cache under `/private/tmp/pquake-refcache`. HTML and
plain-text editor copies were regenerated. Citation targets, source
cross-references, generated HTML fragment links, source line lengths,
trailing whitespace, and `git diff --check` passed. The rendered text was
checked for the final paper-based corrections and comparison values.

These are document-build and consistency checks. They are not a new
cryptographic proof or a reproduction of the paper's tool runs.
