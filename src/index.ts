// ─────────────────────────────────────────────────────────────
// @contexttrust/seal — implementação de REFERÊNCIA do selo V1.2
//
// Este pacote é a fonte canônica do formato. A especificação normativa está em
// ./SPEC.md; quando código e spec divergirem, **a SPEC é a autoridade** e o
// código é o bug.
//
// Invariante do pacote: CÓDIGO PURO. Sem fetch, sem banco, sem env var, sem
// DOM, sem domínio padrão. Só cripto e serialização. É o que permite verificar
// um selo em qualquer lugar — inclusive sem nenhum servidor da trustLayers.
// ─────────────────────────────────────────────────────────────

export {
  // ─── Constantes normativas ───
  SEAL_PROTOCOL_VERSION,
  SEAL_BINDING_DOMAIN,
  SEAL_ID_LENGTH,
  MAX_TIMESTAMP_SKEW_MS,
  LEGACY_V10_CUTOFF,

  // ─── Normalização e hashes (SPEC §2, §3) ───
  normalizeContent,
  hashContent,
  hashMedia,
  createCompositeHash,
  createLegacyCompositeHash,
  generateSealId,

  // ─── Chaves e assinatura (SPEC §5) ───
  generateKeyPair,
  exportKeyPair,
  importKeyPair,
  signHash,
  verifySignature,

  // ─── Selagem e verificação ───
  sealContent,
  verifySeal,
  getVerifyUrl,
} from './seal.js'

export type {
  SealAuthor,
  SealAncestry,
  SealEnvelope,
  SealResult,
  KeyPair,
  VerificationResult,
} from './seal.js'

// Similaridade textual — declarativa, FORA da prova criptográfica (SPEC §4).
export { computeSimhash64, simhashHamming } from './simhash.js'
