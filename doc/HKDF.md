# HMAC-based Key Derivation Function (HKDF)

Extracts from __RFC5869__: [https://tools.ietf.org/html/rfc5869](https://tools.ietf.org/html/rfc5869)

------------------------

## Table of Contents

* [Introduction](#introduction)
* [HMAC-based Key Derivation Function (HKDF)](#hkdf)
    * [Step 1: Extract](#extract)
    * [Step 2: Expand](#expand)
* [Notes to HKDF Users](#notes)
    * [To Salt or not to Salt](#salt)
    * [The ’info’ Input to HKDF](#info)
    * [To Skip or not to Skip](#skip)
    * [The Role of Independence](#independence)

## Introduction

A key derivation function (KDF) is a basic and essential component of cryptographic systems. Its goal is to take some source of initial
 keying material and derive from it one or more cryptographically strong secret keys. This document specifies a simple HMAC-based [HMAC] KDF, named HKDF, which can be used as a building block in various protocols and applications, and is already used in several IETF protocols, including __IKEv2__, __PANA__, and __EAP-AKA__.


HKDF follows the "extract-then-expand" paradigm, where the KDF logically consists of two modules:

1. The first stage __takes the input keying material and "extracts" from it a fixed-length pseudorandom key K__.
2. The second stage __"expands" the key K into several additional pseudorandom keys__ (=the output of the KDF).

In many applications, the input keying material is not necessarily distributed uniformly, and the attacker may have some partial knowledge about it (for example, a Diffie-Hellman value computed by a key exchange protocol) or even partial control of it (as in some entropy-gathering applications).

* Thus, the goal of the "extract" stage is to "concentrate" the possibly dispersed entropy of the input keying material into a short, but cryptographically strong, pseudorandom key.
* The second stage "expands" the pseudorandom key to the desired length; the number and lengths of the output keys depend on the specific cryptographic algorithms for which the keys are needed.

In some applications, the input may already be a good pseudorandom key; in these cases, the "extract" stage is not necessary, and the "expand" part can be used alone.

## <A name="hkdf"></A> HMAC-based Key Derivation Function (HKDF)

<CODE>HMAC-Hash</CODE> denotes the HMAC function instantiated with hash function ’Hash’. HMAC always has two arguments:

1. the first is a key
2. and the second an input (or message).

(Note that in the extract step, <CODE>IKM</CODE> is used as the HMAC input, not as the HMAC key.)

* When the message is composed of several elements we use concatenation (denoted __|__ ) in the second argument
    * for example: <CODE>HMAC(K, elem1 | elem2 | elem3)</CODE>

### <A name="extract"></A> Step 1: Extract

```
HKDF-Extract(salt, IKM) -> PRK
```

* __Options__
    * <CODE>Hash</CODE> a hash function
    * <CODE>HashLen</CODE> denotes the length of the hash function output in octets
* __Inputs__
    * <CODE>salt</CODE> optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
    * <CODE>IKM</CODE> input keying material
* __Output__
    * <CODE>PRK</CODE> a pseudorandom key (of HashLen octets)

The output <CODE>PRK</CODE> is calculated as follows:

```
PRK = HMAC-Hash(salt, IKM)
```

 ### <A name="expand"></A> Step 2: Expand

```
HKDF-Expand(PRK, info, L) -> OKM
```

* __Options__
    * <CODE>Hash</CODE> a hash function
    * <CODE>HashLen</CODE> denotes the length of the hash function output in octets
* __Inputs__
    * <CODE>PRK</CODE> a pseudorandom key of at least <CODE>HashLen</CODE> octets (usually, the output from the extract step)
    * <CODE>info</CODE> optional context and application specific information (can be a zero-length string)
    * <CODE>L</CODE> length of output keying material in octets (<= 255*<CODE>HashLen</CODE>)
* __Output__
    * <CODE>OKM</CODE> output keying material (of <CODE>L</CODE> octets)

The output <CODE>OKM</CODE> is calculated as follows:

```
 N = ceil(L/HashLen)
 T = T(1) | T(2) | T(3) | ... | T(N)
 OKM = first L octets of T

where:
 T(0) = empty string (zero length)
 T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
 T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
 T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
 ...
```

 (where the constant concatenated to the end of each <CODE>T(n)</CODE> is a single octet.)

## <A name="notes"></A> Notes to HKDF Users

This section contains a set of guiding principles regarding the use of HKDF.

A much more extensive account of such principles and design rationale can be found in ["Cryptographic Extraction and Key Derivation: The HKDF Scheme"](http://eprint.iacr.org/2010/264)

 ### <A name="salt"></A> To Salt or not to Salt

* HKDF is defined to operate with and without random salt.

This is done to accommodate applications where a salt value is not available. We stress, however, that the use of salt adds significantly to the strength of HKDF, ensuring independence between different uses of the hash function, supporting "source-independent" extraction, and strengthening the analytical results that back the HKDF design.
 
* Random salt differs fundamentally from the initial keying material in two ways:
    1. it is non-secret
    2. it can be re-used.

As such, salt values are available to many applications. For example, a pseudorandom number generator (PRNG) that continuously produces outputs by applying HKDF to renewable pools of entropy (e.g., sampled system events) can fix a salt value and use it for multiple applications of HKDF without having to protect the secrecy of the salt.

In a different application domain, a key agreement protocol deriving cryptographic keys from a Diffie-Hellman exchange can derive a salt value from public nonces exchanged and authenticated between communicating parties as part of the key agreement (this is the approach taken in __IKEv2__).

* __Ideally, the salt value is a random (or pseudorandom) string of the length <CODE>HashLen</CODE>__
    * Yet, even a salt value of less quality (shorter in size or with limited entropy) may still make a significant contribution to the security of the output keying material.
    * Designers of applications are therefore encouraged to provide salt values to HKDF if such values can be obtained by the application.
* __Some applications may even have a secret salt value available for use__; in such a case, HKDF provides an even stronger security guarantee.
    * An example of such application is __IKEv1__ in its "public-key encryption mode", where the "salt" to the extractor is computed from nonces that are secret; similarly, the pre-shared mode of __IKEv1__ uses a secret salt derived from the pre-shared key.

### <A name="info"></A> The ’info’ Input to HKDF

While the <CODE>info</CODE> value is optional in the definition of HKDF, it is often of great importance in applications. Its main objective is to bind the derived key material to application- and context-specific information.

For example, <CODE>info</CODE> may contain a protocol number, algorithm identifiers, user identities, etc.

* In particular, it may prevent the derivation of the same keying material for different contexts (when the same <CODE>IKM</CODE> is used in such different contexts).
* It may also accommodate additional inputs to the key expansion part, if so desired (e.g., an application may want to bind the key material to its length <CODE>L</CODE>, thus making <CODE>L</CODE> part of the <CODE>info</CODE> field).
* There is one technical requirement from <CODE>info</CODE>: it should be independent of the input key material value <CODE>IKM</CODE>.

### <A name="skip"></A> To Skip or not to Skip

In some applications, the input key material <CODE>IKM</CODE> may already be present as a cryptographically strong key (for example, the premaster secret in TLS RSA cipher suites would be a pseudorandom string, except for the first two octets). In this case, one can skip the extract part and use IKM directly to key HMAC in the expand step. On the other hand, applications may still use the extract part for the sake of compatibility with the general case. In particular, if IKM is random (or pseudorandom) but longer than an HMAC key, the extract step can serve to output a suitable HMAC key (in the case of HMAC this shortening via the extractor is not strictly necessary since HMAC is defined to work with long keys too). Note, however, that if the IKM is a Diffie-Hellman value, as in the case of TLS with Diffie-Hellman, then the extract part SHOULD NOT be skipped. Doing so would result in using the Diffie-Hellman value g^{xy} itself (which is NOT a uniformly random or pseudorandom string) as the key PRK for HMAC.

Instead, HKDF should apply the extract step to <CODE>g^{xy}</CODE> (preferably with a <CODE>salt</CODE> value) and use the resultant <CODE>PRK</CODE> as a key to HMAC in the expansion part.

In the case where the amount of required key bits, <CODE>L</CODE>, is no more than <CODE>HashLen</CODE>, one could use <CODE>PRK</CODE> directly as the <CODE>OKM</CODE>. This, however, is NOT RECOMMENDED, especially because it would omit the use of <CODE>info</CODE> as part of the derivation process (and adding <CODE>info</CODE> as an input to the extract step is not advisable).

### <A name="independence"></A> The Role of Independence

The analysis of key derivation functions assumes that the input keying material (IKM) comes from some source modeled as a probability distribution over bit streams of a certain length (e.g., streams produced by an entropy pool, values derived from Diffie-Hellman exponents chosen at random, etc.); each instance of IKM is a sample from that distribution.

* A major goal of key derivation functions is to ensure that, when applying the KDF to any two values IKM and IKM’ sampled from the (same) source distribution, the resultant keys OKM and OKM’ are essentially independent of each other (in a statistical or computational sense).
    * To achieve this goal, it is important that inputs to KDF are selected from appropriate input distributions and also that inputs are chosen independently of each other (technically, it is necessary that each sample will have sufficient entropy, even when conditioned on other inputs to KDF).
* Independence is also an important aspect of the salt value provided to a KDF.
    * While there is no need to keep the salt secret, and the same salt value can be used with multiple <CODE>IKM</CODE> values, it is assumed that <CODE>salt</CODE> values are independent of the input keying material. In particular, an application needs to make sure that <CODE>salt</CODE> values are not chosen or manipulated by an attacker.
    * As an example, consider the case (as in __IKE__) where the salt is derived from nonces supplied by the parties in a key exchange protocol. Before the protocol can use such salt to derive keys, it needs to make sure that these nonces are authenticated as coming from the legitimate parties rather than selected by the attacker (in IKE, for example this authentication is an integral part of the authenticated Diffie-Hellman exchange).

