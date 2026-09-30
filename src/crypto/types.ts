// Shared types for the adaptor layer. No logic here.

/** A 32-byte x-only encoding, as BIP-340 uses for public keys and nonce points. */
export type XOnly = Uint8Array

/** Parity of R + T, which fixes the sign in every adaptor relation. */
export type SumParity = 'even' | 'odd'

export interface KeyPair {
  /** The raw 32-byte secret as supplied. */
  secretKey: Uint8Array
  /** BIP-340's even-y normalised scalar: d = d' if y(d'G) is even, else n - d'. */
  d: bigint
  /** x-only public key bytes, i.e. bytes(x(d'G)). */
  publicKey: XOnly
}

export interface PreSignature {
  /** x-only encoding of the nonce point R (NOT of R + T). */
  rx: XOnly
  /** The pre-signature scalar s-hat. */
  sHat: bigint
  /** x-only encoding of R + T: the nonce the completed signature will carry. */
  sumX: XOnly
  /** Parity of R + T, recorded so adapt/extract cannot disagree about the sign. */
  parity: SumParity
  /** The challenge e used, so the page can show it rather than recompute silently. */
  e: bigint
}

export interface AdaptorSecret {
  /** The adaptor scalar t. */
  t: bigint
  /** x-only encoding of T = t*G. */
  Tx: XOnly
}

export type ExtractResult =
  | { ok: true; t: bigint; Tx: XOnly }
  | { ok: false; reason: string }

export type PreVerifyResult =
  | { ok: true; e: bigint }
  | { ok: false; reason: string }
