// Pinned adaptor fixtures.
//
// THESE ARE NOT OFFICIAL TEST VECTORS, and the UI says so wherever it renders them.
// There are no standardized single-signer Schnorr-adaptor test vectors to be had:
// BIP-340 covers plain Schnorr only, BIP-327 covers MuSig2 and publishes none for
// adaptors, and secp256k1-zkp ships none either. So these are values this lab
// derived and pinned, and the guard against them being self-confirming is the
// independent re-derivation in adaptor-independent.test.ts -- a separate affine
// BigInt implementation that does not import adaptor.ts and reaches the same
// numbers by a different route.
//
// The set covers all four combinations of the two parities that matter:
//   y(P) even/odd  x  y(R+T) even/odd
// plus one case where t needed no negation to give an even-y T, so both branches of
// the t-normalisation in adaptorPoint are exercised too.
//
// THE LAST ROW IS WRONG ON PURPOSE. Its expected s is the real value + 1. It is
// rendered in the page's fixture table like any other row and must report FAIL. A
// checker only ever seen agreeing proves nothing: if every row passed, a mutation
// that forced the comparison true would change nothing observable. This row is what
// makes the table's green rows mean something.

export interface AdaptorFixture {
  id: string
  label: string
  deliberatelyWrong?: boolean
  keyNegated: boolean
  tNegated: boolean
  parity: 'even' | 'odd'
  secretKeyHex: string
  tRawHex: string
  auxRandHex: string
  expect: {
    t: string
    publicKey: string
    Tx: string
    rx: string
    sumX: string
    e: string
    sHat: string
    s: string
  }
}

export const ADAPTOR_FIXTURE_MESSAGE = 'Alice pays Bob 0.10 units on ledger A'

export const ADAPTOR_FIXTURES: AdaptorFixture[] = [
  {
    id: "peven-sumeven",
    label: "P even-y, R+T even-y",
    keyNegated: false,
    tNegated: true,
    parity: "even",
    secretKeyHex: "0a11ce0000000000000000000000000000000000000000000000000000000001",
    tRawHex: "b0b000000000000000000000000000000000000000000000000000000000001",
    auxRandHex: "0000000000000000000000000000000000000000000000000000000000000001",
    expect: {
      t: "f4f4fffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      publicKey: "b404a8b422f0da0f2cd36c5d1e8eef47b1199ee5d6927bece4b6d3cda2592ccb",
      Tx: "ba308f8662e47c904196a74a6f83b035d4315d924258ccb8a4cdceb80617015a",
      rx: "d522af479e3d2f84799170b4cb0984897e345a8547b12086520f4834e0ec6821",
      sumX: "c72fe69892867ad611341549377cc00fa52af75e02dfa550bf1710d017162a52",
      e: "d07c5ca6063ecbcfddac693c5a9bb1c01be807c668a25dd11deae8a11fd68ed0",
      sHat: "29487a4eda1ac209fd8b02fe87293b5df88c5b316ee66caac7f156b5a12bfbad",
      s: "1e3d7a4eda1ac209fd8b02fe87293b5df88c5b316ee66caac7f156b5a12bfbac",
    },
  },
  {
    id: "peven-sumodd",
    label: "P even-y, R+T odd-y",
    keyNegated: false,
    tNegated: true,
    parity: "odd",
    secretKeyHex: "0a11ce0000000000000000000000000000000000000000000000000000000001",
    tRawHex: "b0b000000000000000000000000000000000000000000000000000000000002",
    auxRandHex: "0000000000000000000000000000000000000000000000000000000000000002",
    expect: {
      t: "f4f4fffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
      publicKey: "b404a8b422f0da0f2cd36c5d1e8eef47b1199ee5d6927bece4b6d3cda2592ccb",
      Tx: "3c749a102b2a2dd16a02bce9caee57183898d58fa2ec2e0fd2dfcf0f7978ea92",
      rx: "b8fd13a101f02b8cee5a51aeb782e26af431446b5494f1be03f87ab65a7b040b",
      sumX: "a57cb8b91070589ac68106811181461841e5bdac297e0f39e346c0f6330ff911",
      e: "4ec05562f7d58af9045679c57747ac873dd6bdbaf49f6ad0dea427cbde14fa6c",
      sHat: "fcd5bf4f2586cfd28277b1e7747f23d8372315baee77fe10b1158cff31c878c6",
      s: "7e0bf4f2586cfd28277b1e7747f23d97c7438d43f2f5dd4f1432e7261923787",
    },
  },
  {
    id: "podd-sumeven",
    label: "P odd-y (key negated), R+T even-y",
    keyNegated: true,
    tNegated: true,
    parity: "even",
    secretKeyHex: "0a11ce0000000000000000000000000000000000000000000000000000000004",
    tRawHex: "b0b000000000000000000000000000000000000000000000000000000000001",
    auxRandHex: "0000000000000000000000000000000000000000000000000000000000000001",
    expect: {
      t: "f4f4fffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      publicKey: "db40e60b7c9b1de76f29d84e273ab06febac1267da95d31420b56a380b50093a",
      Tx: "ba308f8662e47c904196a74a6f83b035d4315d924258ccb8a4cdceb80617015a",
      rx: "e39dc86b16f039516c4f407fd0be186a0db736b7d6dbf85aff6faeb588a66a12",
      sumX: "17f64a6b82312a22bf5b7979fcb859705b92677f6fdea0ed54804f8e4580cb27",
      e: "267dabc1dbf69f932f7533f5ec3961bf0e5199975f33f039c290542004499fe8",
      sHat: "1f9ee47c0caf8ba54f1a5819e03083516b1ad5cccc26f548e50cb6eae0ef16ea",
      s: "1493e47c0caf8ba54f1a5819e03083516b1ad5cccc26f548e50cb6eae0ef16e9",
    },
  },
  {
    id: "podd-sumodd",
    label: "P odd-y (key negated), R+T odd-y",
    keyNegated: true,
    tNegated: true,
    parity: "odd",
    secretKeyHex: "0a11ce0000000000000000000000000000000000000000000000000000000004",
    tRawHex: "b0b000000000000000000000000000000000000000000000000000000000003",
    auxRandHex: "0000000000000000000000000000000000000000000000000000000000000003",
    expect: {
      t: "f4f4fffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
      publicKey: "db40e60b7c9b1de76f29d84e273ab06febac1267da95d31420b56a380b50093a",
      Tx: "c38a8a38899db7e9b332b65642bd25897dadc403f0e2863d1ff99046fb695033",
      rx: "523a18732697be72dcf285938c9b6e0fc0021808274efe7e172e9910dd177c45",
      sumX: "750d49b58fe9bccb327d2cf86828b5b69fe96eb08e7f28ee0b48d9abf28f89a4",
      e: "3370d733223e0aaa4e5b0885cc515068b543cd49bbde2b5157a4a9bc08bad92",
      sHat: "387006b14d4aa6cbe6222bb4a982d8c983bd86a7080e3795dba5369a616138d7",
      s: "437b06b14d4aa6cbe6222bb4a982d8c983bd86a7080e3795dba5369a616138da",
    },
  },
  {
    id: "t-not-negated",
    label: "t already gives even-y T (no t negation)",
    keyNegated: false,
    tNegated: false,
    parity: "even",
    secretKeyHex: "0a11ce0000000000000000000000000000000000000000000000000000000001",
    tRawHex: "b0b000000000000000000000000000000000000000000000000000000000006",
    auxRandHex: "0000000000000000000000000000000000000000000000000000000000000006",
    expect: {
      t: "b0b000000000000000000000000000000000000000000000000000000000006",
      publicKey: "b404a8b422f0da0f2cd36c5d1e8eef47b1199ee5d6927bece4b6d3cda2592ccb",
      Tx: "879998ed50d5e269e925af15233417efe54514c62036b5ab957db9ae17bcf2b6",
      rx: "697157c57ff659dda67468f48c6c245c8bfe3d924d34a3c45f3dd261404fd0d9",
      sumX: "953ad6a909c668ee7fdacc708b9023993316ba552e9385b3245120e28645cdaf",
      e: "d59d14e60753fcf6aad2cf4e565a80245e23066dd98dacca5a01a642658e22ca",
      sHat: "d678ba31f3cbd51f10c8adcffdb8b46999dbbf3c70786accb70684ae1b9bb25c",
      s: "e183ba31f3cbd51f10c8adcffdb8b46999dbbf3c70786accb70684ae1b9bb262",
    },
  },
  {
    id: "deliberately-wrong",
    label: "Deliberately WRONG expected s (this row must fail)",
    deliberatelyWrong: true,
    keyNegated: false,
    tNegated: true,
    parity: "even",
    secretKeyHex: "0a11ce0000000000000000000000000000000000000000000000000000000001",
    tRawHex: "b0b000000000000000000000000000000000000000000000000000000000001",
    auxRandHex: "0000000000000000000000000000000000000000000000000000000000000001",
    expect: {
      t: "f4f4fffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      publicKey: "b404a8b422f0da0f2cd36c5d1e8eef47b1199ee5d6927bece4b6d3cda2592ccb",
      Tx: "ba308f8662e47c904196a74a6f83b035d4315d924258ccb8a4cdceb80617015a",
      rx: "d522af479e3d2f84799170b4cb0984897e345a8547b12086520f4834e0ec6821",
      sumX: "c72fe69892867ad611341549377cc00fa52af75e02dfa550bf1710d017162a52",
      e: "d07c5ca6063ecbcfddac693c5a9bb1c01be807c668a25dd11deae8a11fd68ed0",
      sHat: "29487a4eda1ac209fd8b02fe87293b5df88c5b316ee66caac7f156b5a12bfbad",
      s: "1e3d7a4eda1ac209fd8b02fe87293b5df88c5b316ee66caac7f156b5a12bfbad",
    },
  },]

/** The four parity combinations the edge-case list requires be fixtured. */
export const PARITY_COMBINATIONS = ['peven-sumeven', 'peven-sumodd', 'podd-sumeven', 'podd-sumodd'] as const
