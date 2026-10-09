---
title: "PQuAKE - Post-Quantum Authenticated Key Exchange"
abbrev: "PQuAKE"
category: "info"

docname: draft-uri-cfrg-pquake-latest
submissiontype: IRTF
number:
date:
consensus: false
v: 3
area: "IRTF"
workgroup: "Crypto Forum Research Group"
keyword:

  - PQ
  - Key Exchange
  - Compact
  - Authenticated

venue:
  group: "Crypto Forum Research Group"
  type: Research Group
  mail: "cfrg@irtf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg/"
  github: "mouse07410/pquake-draft"
  latest: "https://mouse07410.github.io/pquake-draft/draft-uri-cfrg-pquake.html"

author:
  - ins: U. Blumenthal
    name: Uri Blumenthal
    org: MIT
    email: uri@ll.mit.edu
    country: United States of America

  - ins: B. Luo
    name: Brandon Luo
    org: MIT
    email: brandon.luo@ll.mit.edu
    country: United States of America

  - ins: S. O'Melia
    name: Sean O'Melia
    org: MIT
    email: sean.omelia@ll.mit.edu
    country: United States of America

  - ins: G. Torres
    name: Gabriel Torres
    org: MIT
    email: gabriel.torres@ll.mit.edu
    country: United States of America

  - ins: D. Wilson
    name: David A. Wilson
    org: MIT
    email: david.wilson@ll.mit.edu
    country: United States of America

normative:
  X.509: RFC5280
  HKDF: RFC5869

informative:
  IKEV2: RFC7296
  EDHOC: RFC9528
  CFRG-PROCESS:
    title: Crypto Forum Research Group Process
    author:
      - {org: Crypto Forum Research Group}
    target: https://wiki.ietf.org/group/cfrg/CFRG-Process
  I-D.sfluhrer-cfrg-ml-kem-security-considerations:
  MQV:
    title: An Efficient Protocol for Authenticated Key Agreement
    author:
      - {ins: L. Law, name: Laurie Law}
      - {ins: A. Menezes, name: Alfred Menezes}
      - {ins: M. Qu, name: Minghua Qu}
      - {ins: J. Solinas, name: Jerry Solinas}
      - {ins: S. Vanstone, name: Scott Vanstone}
    date: 2003-03
    seriesinfo:
      DOI: 10.1023/A:1022595222606
  EAP: RFC5247
  RFC9370:
  I-D.wang-ipsecme-kem-auth-ikev2:
  FIPS203:
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
    author:
      - {org: "National Institute of Standards and Technology"}
    date: 2024-08
    seriesinfo:
      FIPS: "203"
    target: https://csrc.nist.gov/pubs/fips/203/final
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    author:
      - {org: "National Institute of Standards and Technology"}
    date: 2024-08
    seriesinfo:
      FIPS: "204"
    target: https://csrc.nist.gov/pubs/fips/204/final
  HMQV:
    title: "HMQV: A High-Performance Secure Diffie-Hellman Protocol"
    author:
      - {ins: H. Krawczyk, name: Hugo Krawczyk}
    date: 2005
    seriesinfo:
      CRYPTO: "2005"
      "IACR ePrint": "2005/176"
    target: https://eprint.iacr.org/2005/176
  BJM-KA:
    title: Key Agreement Protocols and Their Security Analysis
    author:
      - {ins: S. Blake-Wilson, name: Simon Blake-Wilson}
      - {ins: D. Johnson, name: Don Johnson}
      - {ins: A. Menezes, name: Alfred Menezes}
    date: 1997-12
    seriesinfo:
      DOI: 10.1007/BFb0024447
  CAKE-HI:
    title: "CAKE-HI - Compact Authenticated Key Exchange Hiding Identities"
    author:
      - {ins: U. Blumenthal, name: Uri Blumenthal}
      - {ins: G. Itkis, name: Gene Itkis}
      - {ins: R. Khazan, name: Roger Khazan}
      - {ins: B. Luo, name: Brandon Luo}
      - {ins: S. O'Melia, name: Sean O'Melia}
      - {ins: B. Proulx, name: Brian Proulx}
      - {ins: D. Stott, name: David Stott}
      - {ins: G. Torres, name: Gabriel Torres}
      - {ins: D. A. Wilson, name: David A. Wilson}
    date: 2026-08
    seriesinfo:
      "IACR ePrint": "2026/1749"
    target: https://eprint.iacr.org/2026/1749
  KEMTLS:
    title: Post-Quantum TLS without Handshake Signatures
    author:
      - {ins: P. Schwabe, name: Peter Schwabe}
      - {ins: D. Stebila, name: Douglas Stebila}
      - {ins: T. Wiggers, name: Thom Wiggers}
    date: 2020
    seriesinfo:
      "ACM CCS": "2020"
      "IACR ePrint": "2020/534"
    target: https://ia.cr/2020/534
  KEMTLS-PDK:
    title: More efficient post-quantum KEMTLS with pre-distributed public keys
    author:
      - {ins: P. Schwabe, name: Peter Schwabe}
      - {ins: D. Stebila, name: Douglas Stebila}
      - {ins: T. Wiggers, name: Thom Wiggers}
    date: 2021
    seriesinfo:
      ESORICS: "2021"
      "IACR ePrint": "2021/779"
    target: https://ia.cr/2021/779
  KEMTLS-TAMARIN:
    title: "A tale of two models: formal verification of KEMTLS via Tamarin"
    author:
      - {ins: S. Celi, name: Sofia Celi}
      - {ins: J. Hoyland, name: Jonathan Hoyland}
      - {ins: D. Stebila, name: Douglas Stebila}
      - {ins: T. Wiggers, name: Thom Wiggers}
    date: 2022
    seriesinfo:
      ESORICS: "2022"
      "IACR ePrint": "2022/1111"
    target: https://ia.cr/2022/1111
  NIST-SP-800-227:
    title: "Recommendations for Key-Encapsulation Mechanisms"
    author:
      - {org: "National Institute of Standards and Technology"}
    date: 2025-09
    seriesinfo:
      "NIST SP": "800-227"
      DOI: 10.6028/NIST.SP.800-227
    target: https://csrc.nist.gov/pubs/sp/800/227/final
  BATTARBEE-2025-1228:
    title: Quantum-Safe Hybrid Key Exchanges with KEM-Based Authentication
    author:
      - {ins: C. Battarbee, name: Christopher Battarbee}
      - {ins: C. Striecks, name: Christoph Striecks}
      - {ins: L. Perret, name: Ludovic Perret}
      - {ins: S. Ramacher, name: Sebastian Ramacher}
      - {ins: K. Verhaeghe, name: Kevin Verhaeghe}
    date: 2025
    seriesinfo:
      "IACR ePrint": "2025/1228"
    target: https://eprint.iacr.org/2025/1228
  KYBER-ANONYMITY:
    title: "Post-Quantum Anonymity of Kyber"
    author:
      - {ins: V. Maram, name: Varun Maram}
      - {ins: K. Xagawa, name: Keita Xagawa}
    date: 2023
    seriesinfo:
      PKC: "2023"
      DOI: 10.1007/978-3-031-31368-4_1
    target: https://eprint.iacr.org/2022/1696
  CRYPTOVERIF-PQ:
    title: "Post-quantum sound CryptoVerif and verification of hybrid TLS and SSH key-exchanges"
    author:
      - {ins: B. Blanchet, name: Bruno Blanchet}
      - {ins: C. Jacomme, name: Charlie Jacomme}
    date: 2024-07
    seriesinfo:
      CSF: "2024"
    target: https://bblanche.gitlabpages.inria.fr/publications/BlanchetJacommeCSF24.html
  CKAKE:
    title: "Have Your CKAKE and Eat it, Too: Efficient, Composable KEM-Authenticated Key Exchange"
    author:
      - {ins: M. Arapinis, name: Myrto Arapinis}
      - {ins: C. Battarbee, name: Christopher Battarbee}
      - {ins: M. Doosti, name: Mina Doosti}
    date: 2026
    seriesinfo:
      "IACR ePrint": "2026/249"
    target: https://eprint.iacr.org/2026/249

--- abstract

This document describes Post-Quantum Authenticated Key Exchange (PQuAKE),
a proposed construction for mutual authentication using an ephemeral
key-encapsulation mechanism (KEM) exchange, encapsulations to certified
long-term KEM keys, transcript binding, and explicit key confirmation.
Its target use case is a constrained link where avoiding online
post-quantum handshake signatures may reduce communication or computation.
An optional pre-shared secret is intended to protect encrypted credentials
against active outsiders.

The intended Informational document provides a reference construction,
its design rationale, assumptions, security intuition, and conditions for
safe use. Formal analyses reported for the closely related CAKE-HI
construction are relevant evidence; their applicability to this draft's
precise messages and algorithms remains to be established. Protocol-specific
integration, performance comparisons, and unresolved specification details
are identified separately. This individual proposal does not represent
CFRG consensus or a recommendation to an IETF working group.

--- middle

# Introduction

PQuAKE explores mutual authentication without generating a fresh digital
signature over each handshake. Each party presents a certificate binding
its identity to a long-term KEM public key. Encapsulations to those keys
contribute secrets to the final key derivation, and each party confirms
possession of the derived key using a message authentication code (MAC).
Certificate signatures still require validation; avoiding online handshake
signatures does not remove the need for an authenticated trust mechanism.

## Problem Statement and Intended Use

The target problem is establishing fresh, mutually authenticated session
keys on links where the bandwidth, energy, or implementation cost of
post-quantum handshake signatures matters. Candidate applications include
constrained devices with provisioned trust anchors and repeated connections
to peers with certified KEM keys. The additional KEM ciphertexts,
certificate chains, and message flights also have costs. PQuAKE is useful
only where those costs are acceptable relative to the alternatives.

This is a proposed use case, not evidence that every constrained deployment
needs a new AKE construction. Algorithm choice, credential caching,
fragmentation, loss, latency, and certificate verification can change the
trade-off. A comparison must include both peers' complete transmitted
credentials, all ciphertexts and confirmation values, round trips, memory,
and measured computation and energy on the target platform. This document
does not yet provide a deployment-specific comparison of PQuAKE or claim a
universal bandwidth or power advantage.

Section 7 and Appendix Table 4 of {{CAKE-HI}} give the following handshake
byte counts for its comparison with mutually authenticated TLS 1.3 using
Kyber-1024. The row labels retain the paper's algorithm names.

| Certificate-signature row | CAKE-HI octets | mTLS octets | Difference | Reduction relative to mTLS |
|:--------------------------|---------------:|------------:|-----------:|---------------------------:|
| Dilithium5                | 19,398         | 27,984      | 8,586      | 30.7%                      |
| FALCON1024                | 12,768         | 21,354      | 8,586      | 40.2%                      |

The percentages above are calculated as the difference divided by the
mTLS total. They are not the 44.2% figure in the paper's prose, which
corresponds to dividing 8,586 by the smaller 19,398 total. The comparison
assumes the paper's message flows and estimated certificates; it is not
a measurement of this draft with standardized ML-KEM and ML-DSA encodings.

Appendix Table 3 compares cryptographic operation counts: each CAKE-HI
peer replaces an online signature generation with an additional static
KEM encapsulation and decapsulation. Both designs still validate
certificate signatures. This is evidence about the computational workload,
not measured device energy or end-to-end latency. Section 8 identifies
empirical testing in integrated protocols under bandwidth constraints as
future work. The paper's constrained-link use cases and these comparisons
support further evaluation, but do not constitute a working-group request
for PQuAKE.

## Scope and Publication Objective

The objective is an Informational reference for the PQuAKE construction:
what problem it addresses, why its components are combined this way, which
security claims are supported by analysis, and what is required to use it
securely. It is a candidate building block for higher-level protocols,
subject to their own design and analysis. It does not specify a record
layer, application authorization, a universal key schedule for other
protocols, or general best-practice guidance for KEM authentication.

The CFRG process {{CFRG-PROCESS}} asks proposals to establish practical
relevance and research support. This revision identifies related
constructions and the remaining analysis and interoperability work.
No explicit request from an IETF working group to adopt or depend on
PQuAKE is documented here. Related work demonstrates interest in KEM
authentication, but does not establish demand for this particular exchange.
A future revision should cite concrete requirements and requests if they
become available. Publication as a stable reference for external use is
also a possible objective; the appropriate publication stream remains an
open process question. This document does not presume CFRG adoption.

## Design Rationale and Related Work

The construction separates three tasks. An ephemeral KEM exchange provides
an initial secret and is intended to support forward secrecy. Encryption
under a key derived from that secret protects the credentials against
passive observers. Two encapsulations to certified static KEM keys add
contributions that require the corresponding private keys to recover.
Transcript binding and separate confirmation keys tie those contributions
to the exchange and each peer's role. The security intuition and its
conditions are developed in {{security-analysis}}.

MQV {{MQV}} and HMQV {{HMQV}} are historical examples of authentication
through key agreement with static and ephemeral keys. PQuAKE borrows that
high-level objective, not their algebraic construction or security proofs.
Classical discrete-logarithm assumptions do not give post-quantum security.
The distinction between possessing a key, authenticating an identity, and
confirming a particular session also matters here {{BJM-KA}}.

KEMTLS {{KEMTLS}} replaces online TLS handshake signatures with
KEM-based authentication. It supplies a protocol-specific construction and
analysis against which PQuAKE should be compared. KEMTLS-PDK
{{KEMTLS-PDK}} instead exploits pre-distributed public keys to change the
communication and latency trade-offs. Pre-distributed public keys are
different from PQuAKE's optional symmetric secret for credential hiding.
Neither construction's security proof transfers automatically to PQuAKE.
The Tamarin analyses of KEMTLS {{KEMTLS-TAMARIN}} further illustrate why
both the modeled message flow and the precise security definitions matter.

Muckle# {{BATTARBEE-2025-1228}} studies KEM authentication in a hybrid
key-exchange framework, combining contributions from different types of
key establishment. PQuAKE's three KEM secrets are not by themselves a
claim of hybrid security if one algorithm fails. CKAKE {{CKAKE}} presents
a KEM-authenticated construction with a composable proof in Constructive
Cryptography. It is another relevant comparator, particularly for
composition and forward secrecy; this draft makes no comparable
composability claim.

CAKE-HI {{CAKE-HI}} is the closely related construction for which the
authors report CryptoVerif and Verifpal analyses. Its relationship to the
specific PQuAKE encoding, key schedule, and acceptance rules must be made
explicit before those results support claims about this specification.
The distinctive combination proposed for review here is a symmetric
exchange of certified KEM credentials, mutual static-key encapsulation,
and optional credential hiding against active outsiders using a
pre-shared secret. This description is not a claim of novelty or superiority
over the related work.

## Security Goals and Component Requirements

The intended goals are session-key secrecy, mutual authentication after
key confirmation, fresh keys, replay resistance, and forward secrecy for
completed sessions after subsequent compromise of long-term keys.
Credential confidentiality against passive observers is a separate goal.
Protection against active observers additionally depends on an uncompromised
pre-shared secret and the privacy conditions in {{identity-privacy}}.
These are goals with explicit preconditions, not unconditional guarantees.

The components SHALL satisfy the following requirements:

- KEM shared-secret confidentiality under adaptive chosen-ciphertext
  attack (IND-CCA2), with the selected KEM's input checks and rejection
  behavior implemented correctly.
- Authenticated encryption for certificates, with confidentiality and
  ciphertext integrity under the specified nonce discipline.
- A KDF with extraction and expansion properties sufficient for the
  claimed multi-secret key derivation, with separate domains for credential,
  confirmation, and application keys.
- A collision-resistant transcript hash and a MAC with the PRF and
  unforgeability properties required by the analysis. Unforgeability alone
  is insufficient for the reported identity-hiding argument.
- A certificate signature scheme and validation policy that securely bind
  the accepted peer identity to the correct static KEM public key.

Implicit rejection means that an invalid, correctly sized KEM ciphertext
produces a fallback secret rather than a distinguishable decapsulation
failure. It does not permit bypassing public-key or input-length checks.
IND-CCA2 alone does not establish recipient anonymity or identity hiding.
Where a privacy proof uses IK-CCA2 (key indistinguishability under
chosen-ciphertext attack), that additional property must be stated and
justified for the chosen instantiation; it must not be inferred from
ML-KEM standardization. See {{NIST-SP-800-227}} and
{{I-D.sfluhrer-cfrg-ml-kem-security-considerations}} for KEM use and
implementation considerations.

## Proposed Version 1 Algorithm Suite

The proposed mandatory-to-implement suite for Version 1 is:

- Certificate encryption: AES-256-GCM with a 96-bit nonce and 128-bit tag.
- Ephemeral and static KEMs: ML-KEM-1024 {{FIPS203}}.
- Transcript hash: SHA-384.
- Confirmation MAC: HMAC-SHA-384, without truncation.
- KDF: HKDF-SHA-384 {{HKDF}}.
- Certificate signature: ML-DSA-87 {{FIPS204}}.

Naming these algorithms is not a proof that they instantiate every
idealized assumption of a formal model. In particular, the exact HKDF
Extract/Expand mapping, labels, output lengths, authenticated encryption
inputs, and certificate profile still need to be completed and checked
against the models ({{specification-gaps}}). This revision is not yet a
complete interoperable implementation specification.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Protocol Description

The PQuAKE protocol consists of four steps. Messages within the certificate,
static encapsulation, and confirmation steps may cross in transit. Both
messages of a step MUST be available before deriving values that depend on
that complete step. A party MUST NOT accept the exchange or release
application keys until its peer's confirmation is verified and all
credential and authorization checks have succeeded.

1. Establish an ephemeral KEM secret and exchange encrypted certificates.
2. Encapsulate to each peer's certified static KEM key and exchange ciphertexts.
3. Decapsulate and derive separate confirmation and application keys from
   the ephemeral secret, both static KEM secrets, and the ordered transcript.
4. Exchange and verify key-confirmation MACs.

Malformed messages, authentication-tag failures, invalid certificates,
failed confirmation, and timeouts MUST prevent acceptance. Avoiding
identity-dependent failure signals is an additional privacy requirement;
it does not justify accepting invalid credentials or continuing with
unvalidated KEM inputs. Error handling and the remaining privacy behavior
are discussed in {{error-handling}} and {{identity-privacy}}.

The diagram uses abstract cryptographic operations. `KEM.decap(sk, ct)`
takes the private key first. `ct_i, ss_i` denote the ciphertext and secret
created by the initiator for the responder's static public key `pk_r`;
`ct_r, ss_r` denote those created by the responder for `pk_i`.
`sk_e, pk_e` are an independently generated ephemeral key pair for this
execution. `ss_pre` is an optional, high-entropy pre-shared symmetric secret.
`ss_pre` is the empty octet string when no pre-shared secret is used.
The logical KDF inputs below follow Figure 1 of {{CAKE-HI}}; their exact
HKDF parameter mapping remains to be specified.

`H_i` and `H_r` hash the messages sent by the initiator and responder,
respectively, in protocol-step order. The transcript `T = H_i || H_r`
always places the initiator's hash first, regardless of which party
computes it or the order in which messages arrive. Both parties use the
same ordering in the final KDF. Initiator confirmation covers `H_i || H_r`;
responder confirmation covers `H_r || H_i`, matching Figure 1 of
{{CAKE-HI}}. The hashes are chained: `H_i = H(H(H(pk_e) || e_cert_i)
|| ct_i)` and `H_r = H(H(H(ct_e) || e_cert_r) || ct_r)`.
The exact message encoding and context binding remain specification work
({{specification-gaps}}).

The credential-encryption key provides protection before peer
authentication. It MUST NOT be used as an authenticated application key.
The final key derivation includes `ss_e`, `ss_i`, `ss_r`, and optional
`ss_pre` directly, together with `T`, as in Figure 1 of {{CAKE-HI}}.
The reported analyses permit adversarial knowledge or choice of `ss_pre`
for properties other than identity hiding. Including it is not a claim
of a separately proved PSK-only fallback if all KEM contributions fail.

## Protocol Diagram

    Initiator                                                 Responder
    -------------------------------------------------------------------

    Establish initial secret and exchange encrypted certificates
    ------------------------------------------------------------
    (sk_e, pk_e) <- KEM.keygen()
    { pk_e } -->
                                        (ct_e, ss_e) <- KEM.encap(pk_e)
                                                           <-- { ct_e }
    ss_e <- KEM.decap(sk_e, ct_e)

    k_hid <- kdf_1(ss_e || ss_pre || "HID")
                                  k_hid <- kdf_1(ss_e || ss_pre || "HID")
    e_cert_i <- Enc(k_hid, cert_i)       e_cert_r <- Enc(k_hid, cert_r)
    { e_cert_i } -->                                   <-- { e_cert_r }

    Validate credentials and encapsulate to static KEM keys
    -------------------------------------------------------
    cert_r <- Dec(k_hid, e_cert_r)       cert_i <- Dec(k_hid, e_cert_i)
    Validate cert_r and pk_r            Validate cert_i and pk_i
    (ct_i, ss_i) <- KEM.encap(pk_r)     (ct_r, ss_r) <- KEM.encap(pk_i)
    { ct_i } -->                                           <-- { ct_r }

    Decapsulate and derive keys
    ---------------------------
    ss_r <- KEM.decap(sk_i, ct_r)         ss_i <- KEM.decap(sk_r, ct_i)
    H_i <- H(H(H(pk_e) || e_cert_i) || ct_i)
                           H_i <- H(H(H(pk_e) || e_cert_i) || ct_i)
    H_r <- H(H(H(ct_e) || e_cert_r) || ct_r)
                           H_r <- H(H(H(ct_e) || e_cert_r) || ct_r)
    T <- H_i || H_r                     T <- H_i || H_r
    S <- ss_e || ss_i || ss_r || ss_pre || T
                          S <- ss_e || ss_i || ss_r || ss_pre || T
    k_C_i, k_C_r, k_session             k_C_i, k_C_r, k_session
        <- kdf_2(S)                        <- kdf_2(S)

    Key confirmation (only accept after verifying peer MAC)
    -------------------------------------------------------
    C_i <- HMAC(k_C_i, H_i || H_r)
                                    C_r <- HMAC(k_C_r, H_r || H_i)
    { C_i } -->                                             <-- { C_r }
    Verify C_r and peer policy          Verify C_i and peer policy


## Exchange certificates

During this step, both nodes establish a shared ephemeral key via a KEM,
then use it to encrypt certificates before transmitting them.

The initiator generates a fresh ephemeral key pair and transmits the
public key. The responder validates that key, encapsulates to it, and
returns the ciphertext. The initiator validates the ciphertext's type
and length and decapsulates with its ephemeral private key. Both parties
derive the credential-encryption key from `ss_e` and, if present,
`ss_pre`, then encrypt and transmit their certificates.

Before using a received static KEM key, each party MUST authenticate its
binding to the peer identity using certificate path validation and the
deployment's trust and key-usage policy. Validation includes certificate
signatures, validity periods, and applicable revocation requirements.
An invalid credential MUST NOT lead to successful completion. Identity
acceptance and authorization remain separate from signature verification;
a valid certificate for an unexpected identity does not authenticate the
intended peer. When active identity hiding is required, the decision based
on an out-of-band expected identity MUST be deferred until after key
confirmation, as in Section 6.3 of {{CAKE-HI}}. This does not defer checks
needed to authenticate and validate the static KEM key before using it.

Both directions currently use `k_hid`. AES-GCM nonce uniqueness MUST hold
across both senders using that key. Independently assigning the same nonce
in each direction is unsafe. A deterministic allocation of distinct
96-bit nonces by role, or separate encryption keys by role, must be
specified and reflected in the formal model. This draft does not yet
select that mapping ({{specification-gaps}}).

### Key Derivation of k_hid with preshared secret

`k_hid <- kdf_1(ss_e || ss_pre || "HID");`

### Key Derivation of k_hid without preshared secret

`k_hid <- kdf_1(ss_e || "HID");`

### Initiator

`e_cert_i <- E(k_hid, cert_i);`

### Responder

`e_cert_r <- E(k_hid, cert_r);`

## Encapsulate shared secrets

During this step, both nodes generate an encapsulated secret via a KEM.
The ciphertexts are exchanged.

### Initiator

`(ct_i, ss_i) <- KEM.encap(pk_r);`

### Responder

`(ct_r, ss_r) <- KEM.encap(pk_i);`

## Decapsulate ciphertexts and key derivation

The ciphertexts are decapsulated by both parties. At this point, both
sides have all the shared secrets required to derive a set of session
keys.

### Initiator

`ss_r <- KEM.decap(sk_i, ct_r);`

`H_i <- H(H(H(pk_e) || e_cert_i) || ct_i);`

`H_r <- H(H(H(ct_e) || e_cert_r) || ct_r);`

`T <- H_i || H_r;`

`k_C_i, k_C_r, k_session <- kdf_2(ss_e || ss_i || ss_r || ss_pre || T);`

### Responder

`ss_i <- KEM.decap(sk_r, ct_i);`

`H_i <- H(H(H(pk_e) || e_cert_i) || ct_i);`

`H_r <- H(H(H(ct_e) || e_cert_r) || ct_r);`

`T <- H_i || H_r;`

`k_C_i, k_C_r, k_session <- kdf_2(ss_e || ss_i || ss_r || ss_pre || T);`

These are logical inputs, not a complete definition of HKDF parameters.
The secrets and transcript MUST be encoded unambiguously. Confirmation
keys and application keys MUST be derived in distinct domains.

## Key Confirmation

Key confirmation uses HMAC-SHA-384 under a separate key for each sender
role. The initiator sends `C_i <- HMAC(k_C_i, H_i || H_r)`; the responder
sends `C_r <- HMAC(k_C_r, H_r || H_i)`. The responder verifies `C_i` under
`k_C_i`, and the initiator verifies `C_r` under `k_C_r`, using a
constant-time comparison and the complete 48-octet MAC value.

A party MUST NOT accept a reflected local confirmation as the peer's
confirmation. Direction-specific keys and message types distinguish the
two messages. Successful local verification shows that the peer can
compute the expected confirmation for this transcript, subject to the
assumptions in {{security-analysis}}. It does not show that the peer has
received or verified the local confirmation, or authorize application
access by itself.

## Error Handling {#error-handling}

An active attacker can alter, replay, drop, or reorder messages and can
cause denial of service. Transcript binding and confirmation are intended
to prevent acceptance of an altered exchange, not to guarantee delivery
or availability. Implementations MUST validate message framing, type,
length, algorithm-specific inputs, and expected protocol step before
processing them. Unsupported versions, unexpected message types,
truncated fields, and inconsistent lengths MUST NOT lead to acceptance.

Timeouts and resource limits SHOULD be configurable and bounded. A failed
or abandoned exchange MUST discard its pending key material. A retry MUST
start a new exchange with fresh ephemeral keys and encapsulation
randomness. Transport retransmission, if supplied by an integration, must
be distinguished from advancing protocol state and must not repeat a
message in the logical transcript.

This draft defines no peer-visible error notification. Such behavior,
including any delayed identity-dependent failure, must be specified and
analyzed before active identity hiding can be claimed. Logs, response
timing, error codes, and differences in subsequent traffic can disclose
identities even when certificates are encrypted. Failure handling MUST
preserve validation requirements and MUST NOT provide a decapsulation
validity oracle.

# Protocol Messages

The message formats below describe the proposed exchange. A checksum is
not a cryptographic integrity mechanism; integrity at acceptance depends
on authenticated credential encryption and final transcript confirmation.
The framing and context still require the refinements identified in
{{specification-gaps}}.

## Message Format

A message of the protocol is formatted as follows:

     0               1               2               3 0 1 2 3 4 5 6 7 0
     1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Version    |     Type      |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Data                            ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Version: 8 bits

The version field indicates the format of the initiator hello message.
This document describes version 1.

Type: 8 bits

This field indicates the current step of the protocol.

Length: 16 bits

Length is the length of the data, measured in octets. This field allows
the length of the data to be up to 65535 octets.

Data: variable

This field changes based on the current step of the protocol.

## Hello Messages

The Initiator generates an ephemeral KEM key-pair `(sk_e, pk_e) =
KEM.keygen()` and sends the public key `pk_e` to its intended recipient
(the Responder). The Responder performs encapsulation `(ct_e, ss_e) =
KEM.encap(pk_e)` and sends the ciphertext `ct_e` to the Initiator.

### Initiator Hello

An Initiator Hello message is formatted as follows:


     0               1               2               3 0 1 2 3 4 5 6 7 0
     1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Version    |     Type      |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Ephemeral Public Key                     ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Version: 8 bits

The version field indicates the format of the initiator hello message.
This document describes version 1.

Type: 1

This field indicates the state of the protocol.

Length: 16 bits

Length is the length of the ephemeral public key, measured in octets.
This field allows the length of a ephemeral public key to be up to 65535
octets.

Ephemeral Public Key: variable

The initiator MUST generate a fresh, independent ephemeral key pair for
each new protocol execution and MUST NOT reuse the private key across
executions. Public keys need not be numerically unique with probability
one; freshness requires independent generation with secure randomness.

### Responder Hello

A Responder Hello message is formatted as follows:

     0               1               2               3 0 1 2 3 4 5 6 7 0
     1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Version    |     Type      |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Encapsulated Secret                      ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type: 2

Encapsulated Secret: variable

The size of this field depends on the key encapsulation mechanism used.

## Certificate Exchange

A Certificate Exchange message is formatted as follows:

     0               1               2               3 0 1 2 3 4 5 6 7 0
     1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Version    |     Type      |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Initial Vector      | Encrypted Certificate           ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Authentication Tag       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type: 3 for initiator, 4 for responder

Initial Vector: 96 bits

Encrypted Certificate: variable

Authentication Tag: 128 bits

The certificate is encrypted with the derived key `k_hid`. The nonce
and tag are part of the encrypted-certificate message and must be bound
into the transcript. Nonce allocation across both directions remains to
be specified ({{specification-gaps}}).

## Certificate Format

For now, we use standard X.509 certificate {{X.509}} with OIDs
specifying ML-KEM {{FIPS203}} and ML-DSA {{FIPS204}} correspondingly. Future extensions may use
different certificate formats.

## Encapsulation

An Encapsulation message is formatted as follows:

     0               1               2               3 0 1 2 3 4 5 6 7 0
     1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Version    |     Type      |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Encapsulated Secret                      ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type: 5 for initiator, 6 for responder

Encapsulated Secret: variable

The size of this field depends on the key encapsulation mechanism used.

## Key Confirmation

A Key Confirmation message is formatted as follows:

     0               1               2               3 0 1 2 3 4 5 6 7 0
     1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Version    |     Type      |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Key Confirmation Value                     ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type: 7 for initiator, 8 for responder

Key Confirmation Value: 384 bits (output size of SHA384)

This field is the computed HMAC value of the exchange transcript.

# Initial Considerations for Protocol Integration {#integration}

This section identifies questions for future integration specifications.
It does not define a mapping of PQuAKE messages into an existing protocol
or supply guidance to the corresponding working groups. Each integration
must choose its own key schedule and establish that its negotiated
algorithms, identities, context, transcript, and acceptance rules preserve
the intended security properties. A proof for the standalone construction
is not a proof for the resulting protocol.

## IKEv2

An IKEv2 {{IKEV2}} integration would need to define how the exchange relates
to IKE SA establishment, identity and AUTH payloads, traffic selectors,
and the derivation of IKE and Child SA keys. Negotiation, downgrade
protection, fragmentation, retransmission, and failure handling require a
dedicated specification. RFC 9370 {{RFC9370}} concerns multiple key
exchanges in IKEv2; it does not by itself define PQuAKE authentication.
Existing KEM-authentication work such as
{{I-D.wang-ipsecme-kem-auth-ikev2}} is a separate proposal, not an
endorsement of or dependency on PQuAKE.

## EDHOC

EDHOC {{EDHOC}} has its own authentication methods, transcript hashes,
credential processing, and exporter. Replacing parts of its exchange
with PQuAKE cannot be assumed to preserve those properties or its
communication costs. Any proposed composition needs a complete message
and key-schedule definition and an EDHOC-specific security analysis.
PQuAKE's optional pre-shared secret for credential hiding is a choice of
this construction, not a requirement or proposal for LAKE.

## EAP

A new EAP method would need to meet the EAP key-management framework
{{EAP}}, including method identification, peer/server role mapping,
exported key definitions, session identifiers, channel binding where
applicable, and authentication-server interactions. Fragmentation,
retransmission, and deployment authorization also need specification.
This draft defines neither an EAP method nor its security properties.

# Security Analysis and Formal Evidence {#security-analysis}

This section separates the intended security argument from the evidence
currently associated with the draft. The authors report computational
CryptoVerif and symbolic Verifpal analyses of the closely related CAKE-HI
construction {{CAKE-HI}}. A statement about that modeled construction must
not be presented as a proof of every PQuAKE message format, algorithm
instantiation, or protocol integration.

## Evidence and Model Scope

Sections 5 and 6 of {{CAKE-HI}} report CryptoVerif and Verifpal results
for the construction in its Figure 1. The reported properties and their
model-specific meanings are summarized here. The full versioned models,
proof scripts, and tool versions remain pending incorporation; the results
have not been independently reproduced for this draft.

| Property | CryptoVerif | Verifpal |
|:---------|:------------|:---------|
| Session-key secrecy | Real-or-random secrecy | Symbolic key confidentiality |
| Authentication | Event correspondence | Dishonest-value exclusion at confirmation |
| Freshness | Negligible repeated-key probability | No forced successful reuse |
| Forward secrecy | Restricted static-key exposure | Phase-limited static-key leakage |
| Identity hiding | Equal-length public-key choice game | Credential confidentiality |

The CryptoVerif secrecy experiment additionally permits adversarial
selection of the initiator's ephemeral key pair. Its freshness experiment
compares new keys with stored keys from earlier executions. Identity
hiding requires secret `ss_pre` in both tools. CryptoVerif compares
public-key choices by indistinguishability; Verifpal checks confidentiality
of credential terms, not an unlinkability query. These distinct definitions
must be retained when describing the reported results.

For the CryptoVerif forward-secrecy experiments (Section 5.7), an attacker
may obtain both static private keys while being unable to modify `pk_e`
and `ct_e`, or obtain the initiator's static private key while being unable
to modify `pk_e`. Those experiments do not establish unrestricted active
forward secrecy under arbitrary ephemeral-message modification and
static-key exposure. The Verifpal phase restriction similarly matters.

The execution environment in Section 5.2 assumes prior authentic exchange
of the parties' long-term public keys. Certificates are modeled as public
keys, without metadata or certificate signatures. The CryptoVerif models
permit concurrent executions and use a setup table of valid keys. The
Verifpal models assume knowledge of valid keys, with a membership check
rather than an early expected-identity equality check. These abstractions
leave X.509 parsing, path validation, revocation, and application identity
policy to the specification and implementation analysis.

The two authentication definitions must also be distinguished. CryptoVerif
uses event correspondence with the static KEM secrets as parameters.
Section 5.12 describes a Verifpal authentication definition that can admit
a confirming value generated by the party performing the check. The
reported symbolic result therefore must not be restated as independently
establishing distinct-peer identity agreement or mutual acceptance.

CryptoVerif provides computational evidence under the modeled assumptions.
Verifpal provides a complementary symbolic check; Section 5.10 describes
its search and soundness limits. Neither tool automatically verifies a
wire implementation or an unmodeled error path.

## Primitive Assumptions in the Reported Computational Analysis

Section 5.8 of {{CAKE-HI}} models the final KDF as a random oracle. The
credential KDF is modeled as a PRF, except in the forward-secrecy models
where it is also a random oracle. Domain separation is assumed. The
analysis also requires IND-CCA2 certificate encryption, an IND-CCA2,
implicitly rejecting KEM with IK-CCA2 for identity hiding, a PRF for the
confirmation MAC, and collision resistance of the transcript hash for
freshness. The paper requires the applicable assumptions to hold against
the stated quantum adversary with classical oracle access.

Section 5.13 describes different symbolic abstractions: HKDF, ENC/DEC,
PKE encryption/decryption, MAC/ASSERT, and HASH/CONCAT. These do not validate
all details of a concrete ML-KEM, AES-GCM, or X.509 implementation.

The exact HKDF-SHA-384 mapping and AES-GCM nonce discipline still need to
be checked against the computational assumptions. HMAC's PRF or quantum
security does not alone make every concrete HKDF invocation an ideal
random oracle. Similarly, a sponge-construction result for SHA-3, cited
in Section 5.8 of the paper, does not justify SHA-384, which uses a
different construction. Collision resistance of SHA-384 is an explicit
assumption here and needs its own supporting rationale.

## Relationship to the PQuAKE Specification

This revision aligns the logical diagram with CAKE-HI Figure 1: the
optional pre-shared secret contributes to both KDFs, the transcript uses
chained hashes of encrypted credentials, and the two confirmation MACs
use the corresponding directional transcript order and separate keys.
The original draft's inconsistencies in these values cannot be treated
as already covered by the reported proofs.

A complete mapping still needs the versioned proof artifacts, exact query
and acceptance-event definitions, and a comparison of message encoding,
HKDF instantiation, nonces, credentials, and error behavior. Published
results for CAKE-HI support review of the logical construction; they are
not a completed proof of the PQuAKE wire profile or its integrations.

## Threat Model and Assumptions

The intended network attacker may observe, initiate, interleave, modify,
replay, delay, or suppress exchanges. Credential authenticity depends on
trusted certification authorities, correct path validation, and binding
the validated identity and key to the intended peer. Corrupted endpoints,
compromised trust anchors, implementation side channels, and denial of
service are not excluded by network-message cryptographic arguments.

A security claim must state which static private keys, ephemeral private
keys, encapsulation randomness, pre-shared secrets, and established session
keys can be exposed and when. For the forward-secrecy intuition here,
the exchange completes between honest parties before static-key exposure,
and ephemeral secrets and randomness have been securely erased. No
unrestricted claim under concurrent endpoint compromise is made.

The confidentiality argument relies on KEM shared-secret security,
authenticated encryption, the stated KDF assumptions, and secure randomness.
Authentication additionally relies on credential integrity, static-key
secrecy in the relevant execution, transcript binding, and unforgeable
confirmation MACs. Identity privacy has additional conditions in
{{identity-privacy}}. An ideal random oracle used in an analysis is not
identical to concrete HKDF-SHA-384; that instantiation requires justification.

## Session-Key Secrecy and Forward Secrecy: Intuition

The final key depends on `ss_e`, `ss_i`, `ss_r`, and optional `ss_pre`.
In an honest completed
execution, an outsider should not recover those KEM contributions from
the public keys and ciphertexts. A proof would use the relevant KEM
security games to replace protected contributions with random secrets,
then justify the secrecy of the derived application key under the KDF
assumptions. Merely concatenating secrets is not a complete reduction,
and claims for maliciously chosen inputs or exposed contributions need
the corresponding multi-session analysis.

After later compromise of both static KEM private keys, recorded `ct_i`
and `ct_r` can reveal the static contributions. The intended protection
of the old session key therefore rests on the ephemeral contribution
`ss_e`. Independent ephemeral generation and erasure of `sk_e`, `ss_e`,
and the encapsulation randomness that could reconstruct it are essential.
This explains the forward-secrecy goal for completed sessions; it does
not establish security if ephemeral state was retained or exposed, nor
forward secrecy of certificates against exposure of their encryption key.

## Mutual Authentication and Key Confirmation: Intuition

Consider an attacker impersonating the responder to an honest initiator.
The initiator encapsulates `ss_i` to the static key in the responder's
validated certificate. To produce the expected `C_r`, the attacker needs
a confirmation key depending on that secret and the transcript. Without
the responder's private key or a forgery, it should not obtain the missing
contribution. The corresponding argument for an attacker impersonating
the initiator uses `ss_r`, encapsulated by the honest responder to `pk_i`.

This argument concerns an honest party's challenge to its peer. The
encapsulator already knows the secret it creates: success does not imply
that both parties necessarily ran a particular decapsulation operation.
Relaying an honest exchange also need not reveal its keys to the relay.
A full authentication result must establish agreement on peer identities,
roles, the transcript, and the session, including concurrent sessions.
Certificate validation alone, or equality of derived keys alone, does
not establish that agreement.

Separate `k_C_i` and `k_C_r` prevent simply reflecting the local MAC as
peer confirmation. A valid peer MAC confirms possession of a derived key
for the local transcript. Each party must also validate the expected peer
identity and apply authorization policy before accepting. If confirmation
messages cross, one party's local acceptance does not imply the other
party has accepted.

## Transcript Binding, Freshness, and Replay: Intuition

Both peers derive keys from the same ordered transcript `T`. Altering a
bound message should change the transcript or an underlying secret, so
an old confirmation should no longer verify. Fresh ephemeral keys and
encapsulation randomness are intended to separate executions. Key
freshness is a probabilistic security property, not a guarantee that
random outputs never collide.

The transcript must have an unambiguous encoding and bind message types,
roles, the selected suite, version, and any external application context
that changes the meaning of the exchange. Otherwise identical byte strings
could be interpreted differently, or a valid exchange could be misbound
to a different use. This draft's abstract hashes require the completion
identified in {{specification-gaps}} before replay and identity-agreement
claims can be tied to an interoperable encoding.

## Identity Privacy: Intuition and Limits {#identity-privacy}

Without `ss_pre`, a passive observer is intended to be unable to derive
`k_hid` from the ephemeral KEM traffic. An active attacker, however, can
supply its own ephemeral key or encapsulation and know the resulting
`ss_e`. It can then decrypt a peer's certificate before static-key
authentication finishes. Later failure of key confirmation does not undo
that disclosure.

With an uncompromised, high-entropy `ss_pre`, the credential-encryption
KDF is intended to deny that key to an active outsider even when it
controls the ephemeral exchange. A member of the same Community of
Interest holding that secret has no such protection. This mechanism is
not password authentication: a low-entropy secret can admit offline
guessing using the certificate encryption tag and recognizable plaintext.
The modeled KDF and encryption assumptions must support the claimed
protection for the chosen secret distribution.

Credential encryption alone does not establish anonymity or unlinkability
of the entire exchange. Static-key ciphertexts, certificate lengths,
network addresses, timing, and identity-dependent aborts can distinguish
peers. The CryptoVerif privacy model compares equal-length public keys;
it does not model arbitrary certificate metadata or traffic analysis.
Verifpal's credential-confidentiality query is not the same property.

Section 5.8 of {{CAKE-HI}} invokes the Kyber anonymity result
{{KYBER-ANONYMITY}} to support IK-CCA2. That is relevant evidence, rather
than a property inferred from IND-CCA2 alone. Applying the result to
standardized ML-KEM-1024 requires checking the definitions, algorithm
version, and model instantiation. This draft leaves that mapping open;
it makes no unconditional claim of complete identity hiding.

Section 6 of {{CAKE-HI}} reports two instructive privacy failures in
weaker variants. Early failure based on an out-of-band expected identity
can distinguish peers; the paper delays that decision until the end of
the exchange. Hashing plaintext credentials, combined with a MAC assumed
only unforgeable rather than pseudorandom, can also disclose identity
information. This revision hashes encrypted credentials and retains the
PRF assumption for HMAC. Required credential and input validation still
must hold; implementation timing and failure paths need separate review.

## Limits of the Analysis

Section 5.3 of {{CAKE-HI}} describes polynomially bounded quantum
adversaries with classical oracle access. Section 6.6.2 explicitly leaves
superposition access to random oracles outside its completed analysis.
A result in that model is not a quantum-random-oracle proof. The relevant
post-quantum CryptoVerif methodology is described in
{{CRYPTOVERIF-PQ}}; its applicability depends on the tool version,
transformations, and quantum assumptions used in the actual artifacts.

A post-quantum KEM alone does not establish those properties for a
classical proof or a concrete key schedule. This revision makes neither
a QROM claim nor a universal-composability claim. The paper's suggestion
that its arguments may extend to QROM is future work, not a proven result.

A protocol integration must supply its own composition argument, including
application key derivation, negotiation, and acceptance events. Concrete
security bounds, multi-user effects, key-compromise impersonation,
ephemeral-secret exposure, and stronger identity-agreement properties must
be assessed before claiming them for PQuAKE.

# Security Considerations

Safe use requires both the construction-level conditions above and correct
handling of credentials, keys, messages, and failures. The following
requirements apply to implementations of any completed PQuAKE profile;
they do not resolve the specification gaps listed below.

## Credential Validation and Authorization

Implementations MUST validate the certificate chain and its binding to the
static KEM key, check key usage and algorithm parameters, and enforce the
expected peer identity and authorization policy before acceptance. For
active identity hiding, the identity-dependent decision is deferred until
after confirmation ({{identity-privacy}}). Using
a valid certificate belonging to an unintended peer is not successful
authentication of the intended peer. Certificates containing unsupported
or malformed keys MUST NOT be used for encapsulation. A post-quantum
certificate signature alone does not make a chain with vulnerable
certification keys post-quantum secure.

## Key Lifecycle and Randomness

Implementations MUST use cryptographically secure randomness for key
generation, encapsulation, and any randomized nonce allocation. They MUST
protect static private keys and pre-shared secrets and erase ephemeral
private keys, ephemeral secrets, encapsulation randomness, and intermediate
KDF material when no longer needed. Failed exchanges MUST discard pending
application and confirmation keys. Certificate-encryption and confirmation
keys MUST NOT be reused for application traffic. Static KEM keys SHOULD
be dedicated to the defined protocol use to avoid unreviewed cross-protocol
interactions.

A shared Community-of-Interest secret needs provisioning, rotation,
revocation, and compromise recovery. Possessing it is not individual peer
authentication, and its compromise permits active credential disclosure
within the scope described in {{identity-privacy}}.

## Input Handling and Resource Limits

Implementations MUST validate supported versions and types, exact lengths,
field boundaries, cryptographic input formats, and expected protocol state
before using an input. A 16-bit length field is not sufficient protection
against resource exhaustion. Deployments SHOULD bound concurrent pending
exchanges, credential-chain size and depth, fragmentation buffers, and
processing time. They MUST NOT release decrypted plaintext on AEAD tag
failure or application keys on confirmation failure.

KEM checks and implicit rejection MUST follow the selected algorithm's
specification. Implementations MUST avoid exposing validity through
secret-dependent branches, timing, or distinct decapsulation errors.
Generic parser failures still need bounded and safe handling. Side-channel
and fault resistance require implementation review beyond the abstract
protocol analysis.

## Specification Work Required Before Interoperable Use {#specification-gaps}

The following issues require resolution and review before this draft can
serve as a complete interoperable specification:

- Define each HKDF Extract and Expand invocation, including salt, input key
  material, domain labels, context, output lengths, and the no-pre-shared-secret
  case. Justify the concrete KDF against the formal assumptions.
- Define the exact transcript encoding, including headers, encryption
  nonces and tags, suite and version, role ordering, and external context.
  Specify how validated identities and KEM keys are bound to session
  acceptance and assess unknown-key-share and concurrent-session attacks.
- Allocate AES-GCM nonces safely across both senders under `k_hid`, or
  specify separate directional keys, and define authenticated associated
  data. Include this choice in the formal analysis and test vectors.
- Complete the X.509 KEM-key and signature profile, algorithm identifiers,
  key-usage rules, chain encoding, and trust and revocation requirements.
- Define privacy-preserving failure behavior without bypassing required
  checks, and justify any recipient-anonymity assumption for the concrete
  KEM. Specify credential padding if hiding length is an objective.
- Specify byte order, complete per-type lengths, transport/session
  association, duplicate and retransmission handling, and extension or
  negotiation rules. Until negotiation is defined, a completed Version 1
  profile must use its fixed suite and reject unsupported alternatives.
- Link versioned proof artifacts for the public CAKE-HI paper and supply
  claim-to-model and model-to-specification mappings. Provide reproducible test vectors for
  successful exchanges, wrong peer identities, modified and replayed
  messages, malformed inputs, mismatched pre-shared secrets, and failed
  confirmation.

These items include cryptographic decisions, not just editorial details.
Completing them may require changes to the reported CAKE-HI models. The
current diagram and message layouts must not be treated as an already
validated wire implementation.


# IANA Considerations

None.

--- back

# Acknowledgments
{:numbered="false"}

The authors want to thank Roger Khazan (MIT/LL), Adam Margetts (MIT/LL)
for reviewing this work and giving helpful suggestions. The authors also
thank Guilin Wang for comments on the design rationale, related work,
security explanations, and integration scope, and John Preuß Mattsson and
Nick Sullivan for comments on the scope, applicability, and review process.
