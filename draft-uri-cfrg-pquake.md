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
  IKEV2: RFC7296
  X.509: RFC2459

informative:
  MQV:
    title: An Efficient Protocol for Authenticated Key Agreement
    author:
      - {ins: L. Law, name: Laurie Law}
      - {ins: A. Menezes, name: Alfred Menezes}
      - {ins: M. Qu, name: Minghua Qu}
      - {ins: J. Solinas, name: Jerry Solinas}
      - {ins: S. Vanstone, name: Scott Vanstone}
    date: 1998
    seriesinfo:
      DOI: 10.1023/A:1022595222606
  EAP: RFC5247
  # Bibliography promoted from the former in-line [1]..[34] list.
  # Cite from the body with {{REFNAME}}; uncited entries are not rendered.
  RFC9370:
  I-D.ietf-ipsecme-ikev2-mlkem:
  I-D.wang-ipsecme-kem-auth-ikev2:
  GAZDAG-IKEV2-PQ:
    title: A Formal Analysis of IKEv2's Post-Quantum Extension
    author:
      - {ins: S.-L. Gazdag, name: Stefan-Lukas Gazdag}
      - {ins: S. Grundner-Culemann, name: Sophia Grundner-Culemann}
      - {ins: T. Guggemos, name: Tobias Guggemos}
      - {ins: T. Heider, name: Tobias Heider}
      - {ins: D. Loebenberger, name: Daniel Loebenberger}
    date: 2021-12
    seriesinfo:
      ACSAC: "2021"
      DOI: 10.1145/3485832.3485885
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
  FIPS206:
    title: "FN-DSA (Draft)"
    author:
      - {org: "National Institute of Standards and Technology"}
    date: 2025
    seriesinfo:
      FIPS: "206 (Draft)"
    target: https://csrc.nist.gov/pubs/fips/206/ipd
  LIBOQS:
    title: liboqs
    author:
      - {org: Open Quantum Safe}
    target: https://github.com/open-quantum-safe/liboqs
  CLASSIC-MCELIECE:
    title: Classic McEliece (Round 4)
    author:
      - {ins: D. J. Bernstein, name: Daniel J. Bernstein}
    date: 2022-10
    seriesinfo:
      "NIST PQC": "Round 4"
    target: https://classic.mceliece.org
  LIBMCELIECE-SPEED:
    title: libmceliece speed table
    author:
      - {ins: D. J. Bernstein, name: Daniel J. Bernstein}
    date: 2025-05-06
    target: https://lib.mceliece.org/speed.html
  WOLFSSL-BENCH:
    title: "wolfSSL Benchmark, Appendix G (Intel x86-64, AVX2)"
    author:
      - {org: wolfSSL}
    target: https://www.wolfssl.com/documentation/manuals/wolfssl/appendix07.html
  PQ-CRYSTALS-DILITHIUM:
    title: "pq-crystals/dilithium (SUPERCOP, KabyLake)"
    author:
      - {org: "CRYSTALS team"}
    target: https://github.com/pq-crystals/dilithium
  CHEN-MCELIECE-FPGA:
    title: Complete and Improved FPGA Implementation of Classic McEliece
    author:
      - {ins: P.-J. Chen, name: Po-Jen Chen}
    date: 2022
    seriesinfo:
      CHES: "2022"
    target: https://eprint.iacr.org/2022/412
  HALAK-CORTEX-M0:
    title: Benchmarking NIST-Standardized ML-KEM and ML-DSA on ARM Cortex-M0+ (RP2040)
    author:
      - {ins: B. Halak, name: Basel Halak}
    date: 2025
    seriesinfo:
      arXiv: "2603.19340"
    target: https://arxiv.org/abs/2603.19340
  FRONTIERS-PQ-SESSION:
    title: Design and Implementation of an Authenticated Post-Quantum Session Protocol
    date: 2025-11
    seriesinfo:
      "Frontiers in Physics": "2025"
      DOI: 10.3389/fphy.2025.1723966
    target: https://doi.org/10.3389/fphy.2025.1723966
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
    refcontent: "unpublished manuscript, 14 pp."
  I-D.uri-lake-pquake:
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
  KEMTLS-PSK:
    title: More Efficient KEMTLS with Pre-Shared Keys
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
    title: "A Tale of Two Models: Formal Verification of KEMTLS in Tamarin"
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
  I-D.celi-wiggers-tls-authkem:
  I-D.wiggers-tls-authkem-psk:
  WIGGERS-THESIS:
    title: Post-Quantum TLS
    author:
      - {ins: T. Wiggers, name: Thom Wiggers}
    date: 2024-01
    refcontent: "Ph.D. Thesis, Radboud University"
    target: https://thomwiggers.nl/publication/thesis/
  KORANGA-PQC-BENCH:
    title: Benchmarking Different PQC Libraries
    author:
      - {ins: A. Koranga, name: Aditya Koranga}
    date: 2025
    refcontent: "LinkedIn post"
    target: https://www.linkedin.com/posts/aditya-koranga_pqc-cupqc-postquantumcryptography-activity-7363632983175548929-dkWs/
  RFC8784:
  RFC9867:
  NIST-SP-800-227:
    title: "Recommendation for Key Management: Part 4 - Post-Quantum Cryptography (Draft)"
    author:
      - {org: "National Institute of Standards and Technology"}
    date: 2025
    seriesinfo:
      "NIST SP": "800-227 (Draft)"
    target: https://csrc.nist.gov/publications/detail/sp/800-227/draft
  SHOR1997:
    title: Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer
    author:
      - {ins: P. W. Shor, name: Peter W. Shor}
    date: 1997
    seriesinfo:
      "SIAM J. Comput.": "vol. 26, no. 5, pp. 1484-1509"
      DOI: 10.1137/S0097539795293172
  FALCON:
    title: "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU"
    author:
      - {ins: P.-A. Fouque, name: Pierre-Alain Fouque}
      - {ins: J. Hoffstein, name: Jeffrey Hoffstein}
      - {ins: P. Kirchner, name: Paul Kirchner}
      - {ins: V. Lyubashevsky, name: Vadim Lyubashevsky}
      - {ins: T. Pornin, name: Thomas Pornin}
      - {ins: T. Prest, name: Thomas Prest}
      - {ins: T. Ricosset, name: Thomas Ricosset}
      - {ins: G. Seiler, name: Gregor Seiler}
      - {ins: W. Whyte, name: William Whyte}
      - {ins: Z. Zhang, name: Zhenfei Zhang}
    date: 2020
    seriesinfo:
      "NIST PQC": "Round 3/4 Submission"
    target: https://falcon-sign.info/falcon.pdf
  MCELIECE1978:
    title: A Public-Key Cryptosystem Based On Algebraic Coding Theory
    author:
      - {ins: R. J. McEliece, name: Robert J. McEliece}
    date: 1978
    seriesinfo:
      "DSN Progress Report": "42-44, JPL, pp. 114-116"
    target: https://ipnpr.jpl.nasa.gov/progress_report2/42-44/44N.PDF
  BATTARBEE-2025-1228:
    title: Quantum-Safe Hybrid Key Exchanges with KEM-Based Authentication
    author:
      - {ins: C. Battarbee, name: Christopher Battarbee}
      - {ins: C. Striecks, name: Christoph Striecks}
      - {ins: L. Perret, name: Ludovic Perret}
      - {ins: S. Ramacher, name: Sebastian Ramacher}
      - {ins: K. Verhaeghe, name: Karenina Verhaeghe}
    date: 2025
    seriesinfo:
      "IACR ePrint": "2025/1228"
    target: https://eprint.iacr.org/2025/1228

--- abstract

This document defines the Post-Quantum Authenticated Key Exchange (PQuAKE)
protocol that addresses the needs of bandwidth- and/or power-constrained
environments, while maintaining strong security guarantees.
It accomplishes that by minimizing
the number of bits that need to be exchanged and
by utilizing an implicit peer authentication approach
similar to Menezes-Qu-Vanstone (MQV) design.
This protocol is suitable for
integration into protocols that establish dynamic
secure sessions, such as Extensible Authentication Protocol (EAP),
Internet Key Exchange Version 2 (IKEv2),
or Secure Communications Interoperability Protocol (SCIP).
This protocol has proofs in the verifiers Verifpal and CryptoVerif for
security properties such as secrecy of the session
key, mutual authentication, identity hiding with a pre-shared secret, and forward
secrecy of the session key.
The authors are in the process of publishing the proofs.


--- middle

# Introduction

The primary goal of PQuAKE is to minimize the communication overhead of
Post-Quantum (PQ) public-key cryptography during a key exchange.
Bandwidth or power limited devices may not realistically use alternative
PQ key exchanges such as the TLS handshake protocol to derive a shared
symmetric key, as PQ digital signatures and keys are drastically larger.
This protocol minimizes the communication overhead by reducing the
number of signatures transmitted by each party to one offline-generated
certificate signature. It is designed to be an add-on to such protocols
as EAP {{EAP}}, IKEv2, and others. Since computing a PQ digital
signature typically is more expensive than performing a PQ KEM, there is
a benefit of reduced computational costs.

The overall idea of the implicit authentication of the peers comes from
the {{{MQV}}} protocol.

Both parties MAY have a pre-shared symmetric secret key, usually
distributed among all the members of the given network or Community of
Interest (COI). Adding a pre-shared symmetric key to the key derivation
ensures confidentiality of the peers' identities (certificates) against
active attackers that do not have that pre-shared key.

The protocol maintains the following security guarantees:

- The secure channel between the Initiator and Responder is mutually
authenticated - Key freshness, aka a new key is generated for this
channel, and it hasn't been reused or stale; - If two parties properly
follow the protocol, both parties will compute the same shared keys that
are known only to them; - Perfect Forward Secrecy, aka after the channel
is closed, there is no way for an adversary to break security properties
associated with the shared key established via this protocol; - Security
against replay attacks; - Confidentiality of peers' identities against
passive adversary; - Confidentiality of peers' identities against active
adversary (aka, Man-In-The-Middle) when both peers utilize long-term
pre-shared key.

This protocol has proofs in the verifiers Verifpal and CryptoVerif for
security properties such as secrecy of the session key, mutual
authentication, identity hiding with a preshared secret, and forward
secrecy of the session key. The authors are in the process of publishing
the proofs.

It is important to note that PQuAKE does not replace protocols like the
TLS record protocol, only the handshake protocol. Other protocols such
as IKEv2, SCIP, or EAP may integrate PQuAKE into their key exchange
phase.

## Compliance requirements for the components

The building blocks of this protocol SHALL have the following security
properties:

- Symmetric Key Cryptosystem - IND-CCA2 - Key Encapsulation Mechanism
(KEM) - Implicit, IND-CCA2 and IK-CCA2 - Key Derivation Function 1 -
Random Oracle Hash Function - Key Derivation Function 2 - Random Oracle
Hash Function - Message Authentication Code (MAC) - Pseudorandom
Function

## Mandatory-To-Implement algorithms

While this protocol has been formally proven to work with any KEM, MAC,
and symmetric cipher that exhibit the above properties --
interoperability requires that a Mandatory-To-Implement (MTI) set of
algorithms is specified for the Version 1 of the protocol:

- Enc: AES-GCM-256 - KEM: ML-KEM-1024 - Hash: SHA384 - MAC: HMAC - KDF:
HKDF - Signature: ML-DSA-87


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Protocol Description

The PQuAKE protocol consists of four steps. Within each step, the
exchanges can happen asynchronously, but one step (aka, all of the
exchanges of that step) MUST conclude before the peers can proceed to
the next one. If any step results in an error, the protocol SHOULD
abort. That includes receiving an out-of-order or corrupted message, or
not receiving an expected message within the deployer-configured time
interval. However, the protocol SHOULD only abort at the end of the
protocol if the peer's identity does not match an out-of-band
verification, and an implicit KEM without aborts SHOULD be used.
Ideally, the protocol SHOULD only abort after the key confirmation step
if the reason for aborting is related to the identities of the two
parties.

Currently, no notification to the other party, such as information about
an abnormal completion and/or giving details of the error, is included
in the protocol.

The four steps are the following:

1. Establish an ephemeral symmetric key via hello messages and exchange
encrypted certificates (one MUST use an encryption scheme with IND-CCA2
security and an implicit KEM with IND-CCA2 security and IK-CCA2
security). 2. Encapsulate shared secrets and exchange the ciphertexts.
3. Decapsulate shared secrets, derive key confirmation keys and a
session key. 4. Perform Key Confirmation.

Note that both peers take full transcripts (chain-hashes) of all the
messages they send and receive, and include the resulting hash outputs
among the inputs of the Key Derivation Function (KDF) that gets invoked
to generate shared secrets (first for encrypting certificates, and the
next time - to provide the shared secret that is the purpose of this
protocol).

While both parties have to share their certificates or identities for
authentication, we assume the identities of each party shall remain
confidential to those outside of this exchange. They encrypt their
certificates with a shared symmetric ephemeral key that they generate
via a ephemeral KEM. This key is used to encrypt the certificate and is
an input to the KDF when generating the shared key. The final KDF that
provides the negotiated shared secret, will also include this symmetric
key in its input.

Instead of generating a signature over the handshake transcript like
TLS, PQuAKE performs an implicit authentication of the handshake. It
does this by making the protocol's session key dependent on not only a
series of KEM calculated shared secrets but also dependent on the hashes
of the sent and received messages. Since only their corresponding party,
who they have authenticated, can know those secrets, deriving the same
session key implicitly authenticates each other while creating a shared
secret.

## Protocol Diagram

    Initiator                                                 Responder
    -------------------------------------------------------------------

    Establish confidential link and exchange certificates
    -----------------------------------------------------
    (sk_e, pk_e) <- KEM.keygen()

    { pk_e } -->
                                        (ct_e, ss_e) <- KEM.encap(pk_e)

                                                           <-- { ct_e }

    ss_e <- KEM.decap(ct_e, sk_e)

    k_hid <- kdf_1(ss_pre, ss_e || "HID")
                                    k_hid <- kdf(ss_pre, ss_e || "HID")

    e_cert_i <- Enc(k_hid, cert_i)       e_cert_r <- Enc(k_hid, cert_r)

    { e_cert_i } -->                                   <-- { e_cert_r }


    Encapsulate and send shared secrets
    -----------------------------------
    cert_r <- Dec(k_hid, e_cert_r)       cert_i <- Dec(k_hid, e_cert_i)

    if cert_r is not valid, abort         if cert_i is not valid, abort

    (ct_i, ss_i) <- KEM.encap(pk_r)     (ct_r, ss_r) <- KEM.encap(pk_i)

    { ct_i } -->                                           <-- { ct_r }


    Decapsulate shared secrets and derive session keys
    --------------------------------------------------
    ss_r <- KEM.decap(sk_i, ct_r)         ss_i <- KEM.decap(sk_r, ct_i)

    send_hash <- H(hf, pk_e, e_cert_i, ct_i)
                               send_hash <- H(hf, ct_e, e_cert_r, ct_r)

    recv_hash <- H(hf, ct_e, e_cert_r, ct_r)
                               recv_hash <- H(hf, pk_e, e_cert_i, ct_i)

    S <- ss_e||ss_i||ss_r||send_hash||recv_hash
                            S <- ss_e||ss_i||ss_r||recv_hash||send_hash

    k_C_i, k_C_r, ... <- kdf_2(hf2, S)
                                     k_C_i, k_C_r, ... <- kdf_2(hf2, S)


    Key Confirmation
    ----------------
    { HMAC(k_C_i, recv_hash || send_hash) } -->
                            <-- { HMAC(k_C_r, send_hash || recv_hash) }


## Exchange certificates

During this step, both nodes establish a shared ephemeral key via a KEM,
then use it to encrypt certificates before transmitting them.

The initiator generates an ephemeral key and transmits the encapsulated
secret. The responder MUST decapsulate the ciphertext. Both parties MUST
derive a shared ephemeral key from the encapsulated secret and the
pre-shared secret if it is present. Both parties MUST encrypt and
transmit their certificates. Both parties MUST validate the
certificate's signature. If the verification of a signature fails, the
protocol MUST abort. Implementors need to be careful to avoid aborting
based off the other node's identity until the end of the protocol to
maintain identity hiding of the peer. Note that key encapsulation
mechanism SHOULD be IND-CCA2 and IK-CCA2 secure and SHOULD NOT abort (it
SHOULD be an implicit KEM).

### Key Derivation of k_hid with preshared secret

`k_hid <- kdf_1(ss_pre, ss_e || "HID");`

### Key Derivation of k_hid without preshared secret

`k_hid <- kdf_1(ss_e, "HID");`

### Initiator

`e_cert_i <- E(k_hid, cert_i);`

### Responder

`e_cert_r <- E(k_hid, cert_r);`

## Encapsulate shared secrets

During this step, both nodes generate an encapsulated secret via a KEM.
The ciphertexts are exchanged.

### Initiator

`(ct_r, ss_r) <- KEM.encap(pk_i);`

### Responder

`(ct_i, ss_i) <- KEM.encap(pk_r);`

## Decapsulate ciphertexts and key derivation

The ciphertexts are decapsulated by both parties. At this point, both
sides have all the shared secrets required to derive a set of session
keys.

### Initiator

`send_hash <- hash(pk_e, e_cert_i, ct_i);`

`recv_hash <- hash(ct_e, e_cert_r, ct_r);`

`transcript <- (send_hash, recv_hash);`

`k_C_i, k_C_r, k_session = kdf_2(ss_e, ss_i, ss_r, transcript);`

### Responder

`send_hash <- hash(ct_e, e_cert_r, ct_r);`

`recv_hash <- hash(pk_e, e_cert_i, ct_i);`

`transcript <- (recv_hash, send_hash);`

`k_C_i, k_C_r, k_session = kdf_2(ss_e, ss_i, ss_r, transcript);`

## Key Confirmation

Key confirmation is done by calculating an HMAC of the chain-hash of all
the sent and received messages correspondingly, using the appropriate
Key Confirmation key derived in step 3. The initiator MUST use the key
K~ir~, and the responder MUST use the key K~ri~.

### Initiator

`C_i <- HMAC(k_C_i, send_hash || recv_hash);`

### Responder

`C_r <- HMAC(k_C_r, recv_hash || send_hash);`

## Error Handling

We make no assumptions about the underlying transport that carries
PQuAKE messages, because no error - whether maliciously introduced or
accidental - in any of its messages can impact correctness of the
protocol itself. We consider two kinds of errors:

a. Corruption of a message - will result in protocol failure (abort)

b. Failure to receive a message within expected time interval, aka
timeout - will result in protocol failure (abort).

Handling the protocol timeout (how long to wait until declaring failure
to receive) is the responsibility of the implementation deployer. The
implementer SHOULD make this value configurable.

Note: the more the underlying transport does to detect or mitigate line
errors (aka, non-malicious errors), the likelier the protocol is to
successfully complete. Ideally, the transport would offer at least the
capabilities of UDP.

# Protocol Messages

We do not include explicit checksums because it is practically
impossible for the protocol to succeed if any message would arrive
corrupted, either maliciously, or by a random error.

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

This field SHOULD be unique for each protocol execution.

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

The certificate encrypted with the derived key k\_hid.

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

# Integration into IKEv2

PQuAKE can be integrated into IKEv2 {{IKEV2}} as an alternative
authenticated key exchange mechanism.

One possible approach is:

- Use `IKE_SA_INIT` to perform classical negotiation and optional hybrid
key exchange signaling - Use `IKE_INTERMEDIATE` exchanges to carry
PQuAKE messages - Replace explicit signatures in `IKE_AUTH` with PQuAKE
key confirmation

This results in an implicitly authenticated key exchange, where
authentication is achieved via shared secret derivation rather than
explicit signatures.

This section is **illustrative only**. A complete and interoperable
integration requires a dedicated specification that defines:

- Payload formats - Negotiation mechanisms - Transcript binding - Error
handling and downgrade protection

Such work is out of scope for this document.

# Integration into EDHOC

PQuAKE can be conceptually integrated into EDHOC by replacing or
augmenting its authenticated key exchange phase with PQuAKE's implicit
authentication mechanism.

A possible mapping includes:

- Using EDHOC message_1 / message_2 to carry the ephemeral KEM exchange
- Encrypting credentials using the derived ephemeral secret - Embedding
PQuAKE encapsulation messages into subsequent EDHOC exchanges - Using
EDHOC exporter interface to derive application keys from the PQuAKE
session key

This would preserve EDHOC's compactness while enabling post-quantum
implicit authentication.

This is a **proof-of-concept illustration only**. A production-quality
integration would require a dedicated RFC specifying:

- Message encoding and transcript construction - Credential formats -
Interaction with EDHOC authentication methods - Security analysis
specific to EDHOC composition

# Integration into EAP

PQuAKE may be incorporated into the Extensible Authentication Protocol
(EAP) {{EAP}} as a new EAP method.

In such a design:

- The PQuAKE exchange would form the EAP authentication conversation -
Certificates or identities would be transported within EAP payloads -
The derived session key would be exported via the EAP key hierarchy

This approach enables post-quantum authenticated key exchange for
network access scenarios (e.g., Wi-Fi, 5G, enterprise access).

This is a **proof-of-concept illustration only**. A standards-track
integration would require a dedicated RFC defining:

- EAP method type and state machine - Fragmentation and retransmission
behavior - Key derivation and export interfaces - Interaction with AAA
infrastructure


# Formal Proofs

The security properties of PQuAKE have been analyzed using both symbolic
and computational models, following the methodology developed for
{{CAKE-HI}}.

## Methodology

Two independent formal verification frameworks were used:

- **CryptoVerif** (computational model): - Game-based proofs via
sequence-of-games transformations - Adversary modeled as probabilistic
polynomial-time (PPT), including quantum adversaries with classical
oracle access - **Verifpal** (symbolic model): - Active attacker model
with message modification and replay - Automated reachability and
secrecy analysis

These tools provide complementary assurances: CryptoVerif establishes
computational security under standard assumptions, while Verifpal
validates protocol logic against a wide class of symbolic attacks.

## Proven Security Properties

Under the assumptions listed below, the following properties are
established:

- **Secrecy of the session key**: Reduced to IND-CCA2 security of the
KEM and the random-oracle behavior of KDFs

- **Mutual authentication**: Successful key confirmation implies that
both parties performed correct decapsulation using their respective
long-term secret keys

- **Forward secrecy**: Achieved via inclusion of the ephemeral KEM
shared secret; compromise of long-term keys does not reveal past session
keys

- **Key freshness**: Derived keys are indistinguishable from random and
unique across sessions

- **Identity hiding**: Achieved via encryption of certificates under an
ephemeral shared key, relying on IND-CCA2 encryption and IK-CCA2 KEM
properties

## Cryptographic Assumptions

The proofs rely on the following assumptions:

- KEM is **IND-CCA2** and **IK-CCA2** secure - KEM is **implicitly
rejecting** - KDF behaves as a **random oracle** - HMAC is a
**pseudorandom function (PRF)** - Hash function (e.g., SHA-384) is
**collision-resistant** - Domains of KDF invocations are properly
separated

## Proof Approach (Intuition)

- Secrecy and forward secrecy are obtained by replacing KEM-derived
shared secrets with uniformly random values under IND-CCA2 security,
then applying random oracle arguments to the KDF.

- Authentication follows from the fact that successful key confirmation
requires correct computation of shared secrets derived via decapsulation
with the corresponding private key.

- Identity hiding is obtained by combining: - IND-CCA2 security of
certificate encryption - IK-CCA2 security of the KEM - PRF security of
HMAC

## Limitations and Future Work

- Current proofs rely on the (classical) random oracle model -
Extensions to the quantum random oracle model (QROM) remain future work
- Stronger composability guarantees (e.g., UC-security) are not yet
established

Full formal models and proof artifacts are in the process of
publication.

# Security Considerations

This is a security protocol, and it holds the properties described in
(TODO reference) in the presence of passive or active attacker on the
network.

One potential concern is the confidentiality of the peers' identities
carried in their certificates. An active attacker can learn their
identities during the certificate exchange step. Using a pre-shared
secret will prevent disclosure of these certificates, keeping peers
identities confidential. Since there are costs associated with
out-of-band distribution of that secret, it would be typically shared
among the Community of Interest (CoI). In that case, this protocol would
protect peers identities against active attackers outside of this
Community of Interest, but not against an active attacker that is a
member of CoI.


# IANA Considerations

None.

--- back

# Acknowledgments
{:numbered="false"}

The authors want to thank Roger Khazan (MIT/LL), Adam Margetts (MIT/LL)
for reviewing this work and giving helpful suggestions.
