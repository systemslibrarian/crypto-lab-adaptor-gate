// Cross-ledger swap -- the ledgers are MODELED, the signatures are real.
//
// ROLES (following the brief's ordering: Alice holds the secret and moves first)
//
//   Ledger A  holds Alice's coins, locked to Alice's key P_A, spendable to Bob.
//             Alice PRE-signs it. Bob completes it once he knows t.
//   Ledger B  holds Bob's coins, locked to Bob's key P_B, spendable to Alice.
//             Bob PRE-signs it. Alice completes it -- she chose t, so she can.
//
// Honest order, and the order IS the lesson:
//   1. Alice picks t, publishes T = t*G.
//   2. Both sides pre-sign against the same T and pre-verify what they received.
//   3. Alice completes Bob's pre-signature and publishes s_B on ledger B. She takes
//      Bob's coins -- and in doing so she publishes t to anyone holding s-hat_B.
//   4. Bob READS s_B out of ledger B's state, extracts t, completes Alice's
//      pre-signature, publishes s_A on ledger A.
//
// Step 4 is never handed anything from Alice's side of the model. Bob's t comes from
// `readPublishedSignature(ledgerB)` and nowhere else, which is what makes the
// atomicity claim a result rather than a diagram: before step 3 there is nothing on
// ledger B to read, so step 4 is not merely forbidden, it is not computable.
//
// WHO GETS ROBBED IF A CHECK IS SKIPPED, precisely.
//
// The vulnerable party is BOB, not Alice, and the reason is the ordering. Alice
// holds t, so she can always complete Bob's pre-signature. Bob can only complete
// ALICE's pre-signature, and only with the t he extracts. So if Alice pre-signs her
// side against some T* != T and Bob does not pre-verify:
//
//   - Alice completes Bob's pre-signature with t and takes his coins on ledger B.
//   - Bob extracts t correctly from ledger B. t is the RIGHT secret.
//   - But Alice's pre-signature was built against T*, so completing it with t
//     produces a signature ledger A rejects.
//   - Bob is out his coins on B with nothing on A. Total loss.
//
// Note what the loss is NOT: it is not that Bob extracted the wrong secret, and it
// is not that the cryptography failed. Every check Bob ran passed. The one he
// skipped -- preVerify(pre_A, P_A, m_A, T) -- is the only thing that would have told
// him Alice's pre-signature pointed at a different secret than the payment did.

import { preSign, preVerify, adapt, extract, adaptorPoint, eqBytes } from './adaptor'
import { createLedger, publishSpend, readPublishedSignature, type LedgerState } from './ledger'
import { normaliseSecret, numTo32, hex, N, mod } from './secp'
import type { XOnly, PreSignature } from './types'

export interface SwapOptions {
  /** Alice pre-signs her side against a different T than the payment is locked to. */
  aliceCheats: boolean
  /** Bob does not pre-verify what Alice sent him. */
  bobSkipsPreVerify: boolean
}

export interface SwapStep {
  n: number
  title: string
  detail: string
  /** 'ok' | 'blocked' | 'alarm' -- integrity, not raw return value. */
  status: 'ok' | 'blocked' | 'alarm'
}

export interface SwapRun {
  steps: SwapStep[]
  Tx: XOnly
  TxAlicePreSignedAgainst: XOnly
  alicePublicKey: XOnly
  bobPublicKey: XOnly
  preA: PreSignature
  preB: PreSignature
  /** Did Bob's pre-verification of Alice's pre-signature run, and what did it say? */
  bobPreVerifyRan: boolean
  bobPreVerifyPassed: boolean
  bobPreVerifyReason: string
  ledgerA: LedgerState
  ledgerB: LedgerState
  aliceClaimedB: boolean
  bobClaimedA: boolean
  /** t as Bob computed it, from ledger B's published bytes only. */
  bobExtractedT: bigint | null
  bobExtractedTCorrect: boolean
  /** The guard for invariant 9: Bob's claim attempted BEFORE Alice published. */
  earlyClaimPossible: boolean
  earlyClaimReason: string
  /** True when Bob paid and got nothing -- the fixture the negative claim needs. */
  bobLostFunds: boolean
}

const MSG_A = 'Ledger A: 0.10 units, Alice to Bob'
const MSG_B = 'Ledger B: 1500 units, Bob to Alice'

export const ALICE_SK = numTo32(0x0a11ce00000000000000000000000000000000000000000000000000000000a1n)
export const BOB_SK = numTo32(0x0b0b000000000000000000000000000000000000000000000000000000000b0bn)
const T_REAL = 0x0decaf00000000000000000000000000000000000000000000000000000000abn
const T_FAKE = 0x0badbad0000000000000000000000000000000000000000000000000000000ffn

export function runSwap(opts: SwapOptions): SwapRun {
  const steps: SwapStep[] = []
  const push = (title: string, detail: string, status: SwapStep['status'] = 'ok') =>
    steps.push({ n: steps.length + 1, title, detail, status })

  const alice = normaliseSecret(ALICE_SK)
  const bob = normaliseSecret(BOB_SK)
  const msgA = new TextEncoder().encode(MSG_A)
  const msgB = new TextEncoder().encode(MSG_B)

  // 1. Alice picks t.
  const real = adaptorPoint(T_REAL)
  const fake = adaptorPoint(T_FAKE)
  const tUsedByAliceForHerPreSig = opts.aliceCheats ? fake : real
  push(
    'Alice picks t and publishes T',
    `T = t*G, x(T) = ${hex(real.Tx).slice(0, 16)}...  The payment is locked to this T.`,
  )

  // 2. Both sides pre-sign. Alice's side may be against T*.
  let ledgerA = createLedger('A', alice.publicKey, '0.10 units', MSG_A)
  let ledgerB = createLedger('B', bob.publicKey, '1500 units', MSG_B)

  const preA = preSign(ALICE_SK, msgA, tUsedByAliceForHerPreSig.Tx, { auxRand: numTo32(11n) })
  const preB = preSign(BOB_SK, msgB, real.Tx, { auxRand: numTo32(12n) })
  push(
    'Both sides pre-sign',
    opts.aliceCheats
      ? `Alice pre-signs ledger A against x(T*) = ${hex(fake.Tx).slice(0, 16)}..., NOT the T the payment names.`
      : 'Alice pre-signs ledger A against T; Bob pre-signs ledger B against the same T.',
    opts.aliceCheats ? 'alarm' : 'ok',
  )

  // 3. Pre-verification. Alice always checks Bob's; Bob's check is the toggle.
  const alicePre = preVerify(preB, bob.publicKey, msgB, real.Tx)
  const bobPre = preVerify(preA, alice.publicKey, msgA, real.Tx)
  const bobPreVerifyRan = !opts.bobSkipsPreVerify
  if (bobPreVerifyRan) {
    push(
      'Bob pre-verifies what Alice sent',
      bobPre.ok
        ? "s-hat_A * G == R_adj + e * P_A against the payment's T. Accepted."
        : `REJECTED: ${bobPre.reason}. Bob stops here and loses nothing.`,
      bobPre.ok ? 'ok' : 'blocked',
    )
  } else {
    push(
      'Bob SKIPS pre-verification',
      'Bob accepts the pre-signature without checking which T it commits to.',
      'alarm',
    )
  }
  push(
    'Alice pre-verifies what Bob sent',
    alicePre.ok ? 'Accepted.' : `REJECTED: ${alicePre.reason}`,
    alicePre.ok ? 'ok' : 'blocked',
  )

  // A cheating Alice whose fraud was caught: Bob walks away before paying.
  const bobWalksAway = bobPreVerifyRan && !bobPre.ok

  // 3b. INVARIANT 9 guard: can Bob claim on A before Alice has published on B?
  const earlySig = readPublishedSignature(ledgerB)
  let earlyClaimPossible = false
  let earlyClaimReason = ''
  if (earlySig === null) {
    earlyClaimReason =
      'Ledger B holds no spend yet, so there are no bytes to extract t from. ' +
      "Bob's claim is not forbidden by a rule -- it is not computable."
  } else {
    earlyClaimPossible = true
    earlyClaimReason = 'unexpected: ledger B already held a spend'
  }

  let aliceClaimedB = false
  let bobClaimedA = false
  let bobExtractedT: bigint | null = null
  let bobExtractedTCorrect = false

  if (!bobWalksAway) {
    // 4. Alice completes Bob's pre-signature -- she knows t.
    const completedB = adapt(preB, real.t)
    const pubB = publishSpend(ledgerB, completedB.signature, 'Alice', 3)
    if (pubB.ok) {
      ledgerB = pubB.state
      aliceClaimedB = true
      push(
        'Alice publishes s_B on ledger B',
        `Ledger B accepted the signature and paid Alice. Publishing it also published t ` +
          `to anyone holding s-hat_B -- which is Bob.`,
      )
    } else {
      push('Alice publishes s_B on ledger B', `Ledger B rejected it: ${pubB.reason}`, 'blocked')
    }

    // 5. Bob reads ledger B and extracts. Nothing is handed to him.
    const onChain = readPublishedSignature(ledgerB)
    if (onChain) {
      const ex = extract(preB, onChain, real.Tx)
      if (ex.ok) {
        bobExtractedT = ex.t
        bobExtractedTCorrect = ex.t === real.t
        push(
          'Bob reads ledger B and extracts t',
          `t = s_B - s-hat_B (parity ${preB.parity}) from the published bytes. ` +
            `Recovered t*G == T: ${bobExtractedTCorrect ? 'yes' : 'no'}.`,
        )
      } else {
        push('Bob reads ledger B and extracts t', `Extraction failed: ${ex.reason}`, 'blocked')
      }
    }

    // 6. Bob completes Alice's pre-signature with the t he extracted.
    if (bobExtractedT !== null) {
      const completedA = adapt(preA, bobExtractedT)
      const pubA = publishSpend(ledgerA, completedA.signature, 'Bob', 4)
      if (pubA.ok) {
        ledgerA = pubA.state
        bobClaimedA = true
        push('Bob publishes s_A on ledger A', 'Ledger A accepted it. Both sides are paid.')
      } else {
        push(
          'Bob publishes s_A on ledger A',
          `Ledger A REJECTED it: ${pubA.reason}. Bob extracted the correct t -- ` +
            `Alice's pre-signature was against a different T, so no t could have completed it.`,
          'alarm',
        )
      }
    }
  }

  const bobLostFunds = aliceClaimedB && !bobClaimedA

  return {
    steps,
    Tx: real.Tx,
    TxAlicePreSignedAgainst: tUsedByAliceForHerPreSig.Tx,
    alicePublicKey: alice.publicKey,
    bobPublicKey: bob.publicKey,
    preA,
    preB,
    bobPreVerifyRan,
    bobPreVerifyPassed: bobPre.ok,
    bobPreVerifyReason: bobPre.ok ? '' : bobPre.reason,
    ledgerA,
    ledgerB,
    aliceClaimedB,
    bobClaimedA,
    bobExtractedT,
    bobExtractedTCorrect,
    earlyClaimPossible,
    earlyClaimReason,
    bobLostFunds,
  }
}

export { MSG_A, MSG_B, T_REAL, T_FAKE, eqBytes, mod, N }
