// Exhibit 6 -- the honesty panel (brief act 8). Real / modeled / not implemented,
// the threat model, the negative claims, and the sources.

import { el, card, clear, field } from './dom'
import { VECTOR_COUNTS } from '../crypto/vectors'
import { ADAPTOR_FIXTURES } from '../crypto/fixtures'

export function renderHonesty(root: HTMLElement): void {
  clear(root)

  const intro = card(
    'Not production cryptography — a teaching demo',
    el('p', {
      text:
        'This page runs real BIP-340 Schnorr arithmetic, and the completed signatures it produces ' +
        'are checked by an unmodified library verifier. It is still a teaching demo: keys are ' +
        'generated from values typed into a text box, nothing is constant-time, nothing is ' +
        'persisted, and no part of it should be used to move anything of value.',
    }),
  )
  intro.classList.add('intro')
  root.append(intro)

  const list = el('ul', { class: 'honesty-list reset-list' })
  const row = (tag: 'REAL' | 'MODELED' | 'NOT BUILT', cls: string, text: string) =>
    list.append(
      el(
        'li',
        {},
        el('span', { class: `honesty-tag ${cls}`, text: tag }),
        el('span', { text }),
      ),
    )

  row(
    'REAL',
    'tag-real',
    'secp256k1 arithmetic and BIP-340 tagged hashing, via @noble/curves 2.4.0, checked against ' +
      `BIP-340's own ${VECTOR_COUNTS.total} published test vectors before any lab code was built on it.`,
  )
  row(
    'REAL',
    'tag-real',
    "this lab's adaptor layer: pre-sign, pre-verify, adapt and extract. The signature it finally " +
      "produces is verified by the library's own unmodified BIP-340 verify, never by this lab.",
  )
  row(
    'REAL',
    'tag-real',
    'the nonce-reuse key recovery, run against this lab’s own pre-signing function, and proved ' +
      'by signing a fresh message the library then accepts.',
  )
  row(
    'MODELED',
    'tag-modeled',
    'the ledgers. Two deterministic state machines holding coins whose spend condition is "a valid ' +
      'BIP-340 signature under key P over this message". The signature check is real; there is no ' +
      'chain, script, mempool or fee. A real deployment would lock coins in a 2-of-2 joint key with ' +
      'a timelocked refund — see the MuSig Gate lab — and this lab models the lock so the ' +
      'adaptor arithmetic stays in view.',
  )
  row(
    'MODELED',
    'tag-modeled',
    'timelocks. A step counter that enables a refund path. Not a consensus mechanism.',
  )
  row(
    'MODELED',
    'tag-modeled',
    'PTLC routing. Three hops, real pre-signatures, no channel state, no fees, no network, no onion ' +
      'routing, no retries.',
  )
  row(
    'NOT BUILT',
    'tag-absent',
    'ECDSA adaptor signatures. They need a different and more involved construction and are not ' +
      'implemented here in any form.',
  )
  row('NOT BUILT', 'tag-absent', 'MuSig2 adaptor signatures, and any multi-party signing at all.')
  row('NOT BUILT', 'tag-absent', 'any network, any real chain data, and anything resembling Bitcoin or Lightning.')
  row(
    'NOT BUILT',
    'tag-absent',
    'post-quantum or lattice adaptor constructions. They exist; nothing here touches them.',
  )
  root.append(card('What is real, what is modeled, what is absent', list))

  root.append(
    card(
      'Threat model',
      el(
        'ul',
        { class: 'plain-list' },
        el('li', {
          text:
            'The signer is honest but may reuse nonces. That is the Break It exhibit, and the ' +
            'naive mode is never the default.',
        }),
        el('li', {
          text:
            'A counterparty may send a malformed or wrong-T pre-signature. Pre-verification is the ' +
            'only defence and the swap exhibit shows what skipping it costs.',
        }),
        el('li', {
          text: 'The modeled ledgers are assumed honest and live. Nothing here models a reorg, a censoring miner or a stalled chain.',
        }),
        el('li', {
          text:
            'The security of an honest pre-signature rests on the discrete logarithm problem in the ' +
            'random-oracle model. Gerhart, Schröder, Soni and Thyagarajan re-prove Schnorr ' +
            'adaptor signatures under strengthened definitions (EUROCRYPT 2024).',
        }),
      ),
    ),
  )

  root.append(
    card(
      'What this does NOT prove',
      el(
        'ul',
        { class: 'plain-list' },
        el('li', {
          id: 'negative-claim-presig',
          text:
            'A pre-signature alone does not verify as a signature, and it does not reveal t. What ' +
            'it does do is pin WHICH t would complete it — so it is a commitment to the secret, ' +
            'not a leak of it.',
        }),
        el('li', {
          id: 'negative-claim-preverify',
          text:
            'A correct extraction does not mean a swap was safe. Extraction can return exactly the ' +
            'right secret while the counterparty’s pre-signature committed to a different one, ' +
            'and no check on this page raises a failure code for that. There is no code to raise: ' +
            'the absence of one is the exhibit. Only pre-verifying against the T the payment names ' +
            'detects it.',
        }),
        el('li', {
          text:
            'Per-hop decorrelation is an algebraic property of the identifiers only. It does not ' +
            'make a routed payment private: amounts, timing and topology all still correlate, and ' +
            'none of them are modeled here.',
        }),
        el('li', {
          text:
            'Passing this lab’s fixtures does not establish conformance to anything. There are ' +
            `no official adaptor vectors to conform to, so the ${ADAPTOR_FIXTURES.length - 1} correct ` +
            'fixtures here are self-derived and cross-checked against an independent ' +
            're-implementation — which is evidence, not certification.',
        }),
      ),
    ),
  )

  root.append(
    card(
      'This lab does not teach Schnorr',
      el(
        'p',
        {},
        document.createTextNode('It assumes it. A BIP-340 signature is '),
        el('code', { text: 's = k + e·d' }),
        document.createTextNode(
          ' with the nonce point and key committed into the challenge; if that is unfamiliar, start with ',
        ),
        el(
          'a',
          {
            href: 'https://systemslibrarian.github.io/crypto-lab-schnorr-forge/',
            target: '_blank',
            rel: 'noopener noreferrer',
          },
          document.createTextNode('Schnorr Forge'),
        ),
        document.createTextNode(
          ' and come back. For the 2-of-2 joint key this lab models as a single-key lock, see ',
        ),
        el(
          'a',
          {
            href: 'https://systemslibrarian.github.io/crypto-lab-musig-gate/',
            target: '_blank',
            rel: 'noopener noreferrer',
          },
          document.createTextNode('MuSig Gate'),
        ),
        document.createTextNode('.'),
      ),
    ),
  )

  root.append(
    card(
      'Sources',
      el(
        'ul',
        { class: 'plain-list' },
        el('li', {
          text:
            'BIP-340, Schnorr Signatures for secp256k1 — the specification, and the ' +
            'test-vectors.csv this page runs.',
        }),
        el('li', {
          text:
            'Aumayr, Ersoy, Erwig, Faust, Hostáková, Maffei, Moreno-Sanchez and Riahi, ' +
            '"Generalized Channels from Limited Blockchain Scripts and Adaptor Signatures", ' +
            'ASIACRYPT 2021, pp. 635-664 (ePrint 2020/476) — the game-based security ' +
            'definitions the field standardised on. Their paper describes itself as the first ' +
            'standalone formalization; priority is contested. Fournier, "One-Time Verifiably ' +
            'Encrypted Signatures A.K.A. Adaptor Signatures" (October 2019) claims the same ground ' +
            'six months earlier, and Aumayr et al. cite it as concurrent and weaker while Gerhart ' +
            'et al. do not cite it at all. Both are reported here rather than adjudicated.',
        }),
        el('li', {
          text:
            'Gerhart, Schröder, Soni and Thyagarajan, "Foundations of Adaptor Signatures", ' +
            'EUROCRYPT 2024, LNCS 14652 (Part II), pp. 161-189 (ePrint 2024/1809) — ' +
            'strengthened definitions, with Schnorr adaptor signatures re-proved.',
        }),
        el('li', {
          text:
            'Poelstra, "Scriptless Scripts", slides, MIT Bitcoin Expo, 4 March 2017, with the ' +
            'construction itself first appearing in "Lightning in Scriptless Scripts" on the ' +
            'mimblewimble mailing list, 20 March 2017. Background, never a specification.',
        }),
      ),
      field('library', '@noble/curves 2.4.0 (secp256k1, schnorr)'),
      field('vector file', 'bip-0340/test-vectors.csv, bitcoin/bips, fetched 2026-09-29'),
    ),
  )
}
