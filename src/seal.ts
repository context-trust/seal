/**
 * trustLayers Seal Engine
 *
 * Cryptographic sealing: BLAKE3-256 + Ed25519
 * Protocol: cøntextTrust V7.5.0
 */

import { blake3 } from '@noble/hashes/blake3.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import * as ed25519 from '@noble/ed25519'
// Extensão .js OBRIGATÓRIA: o ESM do Node resolve o caminho literal, e sem
// ela o pacote publicado quebra com ERR_MODULE_NOT_FOUND em `dist/simhash`.
// (`index.ts` já usava .js; só esta linha ficou de fora.) O TypeScript
// entende '.js' apontando para o '.ts' compilado — é a forma canônica.
import { computeSimhash64 } from './simhash.js'

// ─── Types ───────────────────────────────────────────────────────

export interface SealAuthor {
  displayName: string
  pubkey: string
  handle?: string
}

/**
 * V1.2 (27/mai/2026): cadeia de custódia nativa
 *
 * `ancestry` permite vincular UM novo selo a N selos anteriores, criando uma
 * linhagem programática verificável. Os `sealIds` listados entram no
 * compositeHash (via createCompositeHash) → ou seja, viram parte da prova
 * criptográfica e da âncora on-chain. Alterar qualquer sealId da linhagem
 * depois invalida a assinatura.
 *
 * Não há limite hard de tamanho do array; cada cliente decide quantos
 * antecessores referenciar (1 = elo simples, N = "todos os meus selos
 * anteriores formam minha cadeia até aqui").
 *
 * Backward-compat: selos V1.1 (sem ancestry) seguem 100% válidos. Selos V1.2
 * com `ancestry` vazio ou ausente são cryptograficamente idênticos a V1.1.
 */
export interface SealAncestry {
  /** Lista de sealIds antecessores referenciados nesta selagem (8-16 hex chars cada). */
  sealIds: string[]
  /** Selo-raiz declarado (opcional · primeiro da chain conhecida pelo autor). */
  rootSealId?: string
  /** Timestamp da declaração (idêntico a envelope.timestamp.utc — tautológico, atesta consistência). */
  declaredAt: string
}

export interface SealEnvelope {
  version: string
  protocol: string
  contentHash: string
  compositeHash: string
  signature: string
  author: SealAuthor
  timestamp: {
    utc: string
    unix: number
  }
  sealId: string
  verifyUrl: string
  platforms: string[]
  /** Tipo declarativo de conteúdo (document/legal/patent/scientific/book/art/music/prescription/social).
   *  Metadado — NÃO entra no compositeHash/assinatura (igual a platforms). */
  contentType?: string
  /** V1.2 · linhagem programática (ver SealAncestry). Opcional p/ backward-compat. */
  ancestry?: SealAncestry
  /** Cofre privado opcional — payload confidencial cifrado (VAULT_V1:salt:iv:ct,
   *  AES-256-GCM com chave PBKDF2 da passphrase do autor; ver lib/vault).
   *  Metadado top-level — NÃO entra no compositeHash (o GCM tem tag própria de
   *  integridade). Quem tiver a passphrase decifra no próprio navegador. */
  vault?: string
  /** Dados do dispositivo que selou (navegador/SO/tela/fuso/etc) — provenance
   *  descritiva capturada no cliente no momento da selagem. Metadado top-level:
   *  NÃO entra no compositeHash/assinatura. Em selo privado/cifrado é redigido/cifrado. */
  device?: Record<string, unknown>
  /** Identificação da rede da selagem (IP público + DNS reverso + geo aprox. por IP,
   *  observados pelo servidor; + qualidade da conexão do cliente). Provenance descritiva
   *  top-level: NÃO entra no compositeHash/assinatura. Redigida em privado/cifrado/protegido. */
  network?: Record<string, unknown>
  content: {
    text: string
    mediaHashes?: string[]   // SHA-256 calculado no cliente (integridade)
    mediaUrls?: string[]     // URLs diretas do CDN (ex: Vercel Blob public URL)
    mediaCIDs?: string[]     // Content IDs (SHA-256 hex) — âncora determinística no Vault IPFS
    ipfsCids?: string[]      // CIDs IPFS v1 reais (bafy…/bafk…) de Pinata/Filebase — paralelo aos mediaCIDs (index-aligned)
    ipfsGateways?: string[]  // Gateway URL do provider que pinou (um por arquivo, index-aligned)
    // ─── Perceptual hash (off-chain, index-aligned com mediaHashes) ─────
    // Strings vazias '' significam "não computado" ou "não aplicável" (não imagem).
    // NUNCA entra no compositeHash V1.1 — é metadado descritivo, não prova criptográfica.
    // Threshold canônico de similaridade: Hamming ≤6 (64-bit) ou ≤24 (256-bit).
    mediaPerceptualHashes?: string[]      // pHash 64-bit DCT (16 hex chars)
    mediaPerceptualHashes256?: string[]   // pHash 256-bit DCT (64 hex chars)
    // ─── Metadados extraídos pelo servidor (não-editável, descritivo) ───
    // Cada selo tem no máximo 1 mídia (regra 18/mai); arrays mantidos no
    // shape histórico pra retrocompat com selos antigos. NÃO entram no
    // compositeHash V1.1 — são informação verificável derivada dos bytes.
    mediaMetadata?: unknown[]      // JSON estruturado { universal, image, exif, pdf, text }
    mediaMetadataText?: string[]   // versão human-readable / determinística por mídia
    // SimHash 64-bit do texto (off-chain, declarativo) — similaridade por Hamming.
    // NÃO entra no compositeHash/assinatura. Ausente em selos só-mídia (texto vazio).
    contentSimhash?: string
    // Fingerprint perceptual de áudio/vídeo (worker dedicado; { kind, algo, ... }).
    // Off-chain, índice-aligned com mediaHashes. NÃO entra no compositeHash.
    mediaFingerprints?: unknown[]
    /** Mídia CIFRADA (AES-256-GCM via senha) — os bytes em mediaUrls são ciphertext
     *  TLE1, não a imagem. A /verify pede a senha e decifra no navegador do dono.
     *  Usado em selos privados. mediaHashes segue sendo o hash do PLAINTEXT (a
     *  assinatura atesta o original). NÃO entra no compositeHash (metadado). */
    mediaEncrypted?: boolean
    /** Conteúdo (texto + autor) CIFRADO num bundle VAULT_V1 — selos do tipo
     *  `cifrado` e `protegido`. Quando presente, `content.text` e
     *  `author.displayName` ficam '' no envelope (zero-knowledge: o servidor
     *  NUNCA tem o plaintext nem a senha). A /verify decifra `encBundle` no
     *  navegador com a senha do usuário → { text, displayName, handle }.
     *  contentHash/compositeHash/signature seguem sendo do conteúdo ORIGINAL
     *  (calculados na selagem, antes de apagar o texto) → a prova criptográfica
     *  permanece íntegra e o cliente re-valida hashContent(text)===contentHash
     *  após decifrar. NÃO entra no compositeHash (metadado). */
    encBundle?: string
    /** Assuntos declarados pelo autor na selagem (rede social — segmentação do
     *  feed). Slugs da taxonomia fixa (SEAL_TOPICS). Descritivo/portável no
     *  envelope; NÃO entra no compositeHash V1.1 (candidato a V1.2). */
    topics?: string[]
    /** True quando o conteúdo está cifrado em `encBundle` (selo cifrado/protegido).
     *  Sinaliza pra verifySeal pular o re-hash do texto (que está ''/ausente) e
     *  provar a integridade só via compositeHash + assinatura. */
    contentEncrypted?: boolean
  }
}

export interface SealResult {
  envelope: SealEnvelope
  verifyUrl: string
  sealId: string
}

export interface KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

// ─── Core Functions ──────────────────────────────────────────────

/**
 * Generate a new Ed25519 keypair for signing
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = ed25519.utils.randomSecretKey()
  const publicKey = await ed25519.getPublicKeyAsync(privateKey)
  return { privateKey, publicKey }
}

/**
 * Export keypair to hex strings for storage
 */
export function exportKeyPair(kp: KeyPair): { privateKey: string; publicKey: string } {
  return {
    privateKey: bytesToHex(kp.privateKey),
    publicKey: bytesToHex(kp.publicKey),
  }
}

/**
 * Import keypair from hex strings
 */
export function importKeyPair(hex: { privateKey: string; publicKey: string }): KeyPair {
  return {
    privateKey: hexToBytes(hex.privateKey),
    publicKey: hexToBytes(hex.publicKey),
  }
}

/**
 * Normalize content for deterministic hashing
 */
export function normalizeContent(text: string): string {
  // 1. Normalize Unicode to NFC
  let normalized = text.normalize('NFC')
  // 2. Trim trailing whitespace per line
  normalized = normalized.split('\n').map(line => line.trimEnd()).join('\n')
  // 3. Trim trailing newlines
  normalized = normalized.trimEnd()
  return normalized
}

/**
 * Hash content using BLAKE3-256
 */
export function hashContent(content: string): string {
  const bytes = utf8ToBytes(content)
  const hash = blake3(bytes)
  return bytesToHex(hash)
}

/**
 * Hash binary data (for images/media)
 */
export function hashMedia(data: Uint8Array): string {
  const hash = blake3(data)
  return bytesToHex(hash)
}

// SEC-FIX (SEAL-CRIT-01): replay-attack protection — bind composite hash a chain + protocol version
// Estes valores DEVEM ser idênticos client e server side. Mudar requer migration de selos antigos
// (ou tolerância na verifySeal).
export const SEAL_PROTOCOL_VERSION = '1.2.0'  // V1.2 = cadeia de custódia nativa (campo ancestry)
export const SEAL_BINDING_DOMAIN = 'cøntextTrust:polygon-mainnet:137'

/**
 * Create composite hash: content + media + author pubkey + binding domain
 *
 * SEC-FIX (SEAL-CRIT-01 — 2026-04-15 noite): adicionado SEAL_BINDING_DOMAIN
 * pra prevenir replay cross-chain / cross-version. A assinatura agora é válida
 * APENAS na (chain, contract version) específica.
 *
 * Backward-compat: selos V1.0 (sem binding) continuam validáveis via legacy path.
 */
export function createCompositeHash(
  contentHash: string,
  mediaHashes: string[],
  authorPubkey: string,
  bindingDomain: string = SEAL_BINDING_DOMAIN,
  /** V1.2 (27/mai/2026): linhagem programática. Quando presente e não-vazia,
   *  sealIds (sorted canonical) viram parte do compositeHash → alterar a chain
   *  invalida a assinatura. Backward-compat: undefined/empty produz hash
   *  idêntico ao V1.1 (selos sem chain seguem válidos sem mudança). */
  ancestrySealIds?: string[]
): string {
  const parts = [contentHash, ...mediaHashes.sort(), authorPubkey, bindingDomain]
  if (ancestrySealIds && ancestrySealIds.length > 0) {
    // Extensão V1.2: sealIds em ordem canônica (sort lex), prefixados com
    // tag "ancestry:" pra domain separation contra colisão semântica improvável.
    const ancestryStr = 'ancestry:' + ancestrySealIds.slice().sort().join(',')
    parts.push(ancestryStr)
  }
  const combined = parts.join(':')
  return hashContent(combined)
}

/**
 * Legacy compositeHash V1.0 (sem binding) — usado APENAS pra verificar selos antigos
 */
export function createLegacyCompositeHash(
  contentHash: string,
  mediaHashes: string[],
  authorPubkey: string
): string {
  const combined = [contentHash, ...mediaHashes.sort(), authorPubkey].join(':')
  return hashContent(combined)
}

/**
 * Generate seal ID from composite hash.
 * CRIT-003 FIX (V7.7.0): aumentado de 8 para 16 hex chars (64 bits de entropia).
 * Birthday paradox: p(colisão)=50% agora em ~4 bilhões de seals (vs ~65k com 8 chars).
 */
export const SEAL_ID_LENGTH = 16

export function generateSealId(compositeHash: string): string {
  return compositeHash.substring(0, SEAL_ID_LENGTH)
}

/**
 * Normaliza chave para bytes, aceitando hex OU Uint8Array.
 *
 * 🔴 Por que isto existe (P107, 5/ago/2026): até o `@noble/ed25519` 2.x, passar
 * uma chave em **hex string** funcionava por tolerância da biblioteca. A v3 passou
 * a exigir `Uint8Array` e estoura `TypeError: expected Uint8Array of length 32`.
 * A assinatura de tipo daqui sempre disse `Uint8Array` — mas o teste de produção
 * passava hex e ninguém percebeu, porque TypeScript não checa em runtime.
 *
 * ⇒ Em vez de empurrar a conversão para cada chamador (o `hexToBytes` já aparecia
 * em 4 lugares diferentes do app), a normalização mora aqui, num lugar só. Em todo
 * o resto do sistema — envelope, `vectors.json`, banco — pubkey e assinatura vivem
 * como hex; converter na fronteira é o desenho honesto.
 *
 * ⚠️ Formato errado FALHA aqui, com mensagem clara — não silenciosamente lá dentro.
 */
function paraBytes(chave: Uint8Array | string, tamanho: number, nome: string): Uint8Array {
  if (chave instanceof Uint8Array) {
    if (chave.length !== tamanho) {
      throw new TypeError(`${nome}: esperado ${tamanho} bytes, veio ${chave.length}`)
    }
    return chave
  }
  if (typeof chave !== 'string' || !new RegExp(`^[0-9a-fA-F]{${tamanho * 2}}$`).test(chave)) {
    throw new TypeError(`${nome}: esperado Uint8Array de ${tamanho} bytes ou hex de ${tamanho * 2} chars`)
  }
  return hexToBytes(chave.toLowerCase())
}

/**
 * Sign a hash with Ed25519
 */
export async function signHash(
  hash: string,
  privateKey: Uint8Array | string
): Promise<string> {
  const message = utf8ToBytes(hash)
  const signature = await ed25519.signAsync(message, paraBytes(privateKey, 32, 'privateKey'))
  return bytesToHex(signature)
}

/**
 * Verify a signature
 */
export async function verifySignature(
  hash: string,
  signature: string,
  publicKey: Uint8Array | string
): Promise<boolean> {
  const message = utf8ToBytes(hash)
  const sigBytes = paraBytes(signature, 64, 'signature')
  return await ed25519.verifyAsync(sigBytes, message, paraBytes(publicKey, 32, 'publicKey'))
}

/**
 * Monta a URL de verificação de um selo.
 *
 * ⚠️ `baseUrl` é OBRIGATÓRIO e NÃO tem default. Isto é deliberado: **o protocolo
 * não tem domínio.** Quem sela escolhe onde o selo pode ser consultado; um
 * default aqui transformaria uma implementação específica em autoridade.
 *
 * ⚠️ `verifyUrl` **NÃO entra no compositeHash nem na assinatura** (§4 da SPEC).
 * É metadado de conveniência: um selo NÃO prova onde foi criado, e alterar este
 * campo não invalida nada. A verificação de um selo nunca deve depender dele —
 * use o `compositeHash` e, quando houver, a prova de inclusão on-chain.
 *
 * Contexto histórico: no app de origem este parâmetro tinha default para um
 * domínio de terceiro (`trustlayers.io`), o que teria gravado uma URL alheia
 * dentro de envelopes. Nenhum selo foi afetado, mas a lição virou regra: sem
 * default, nunca.
 */
export function getVerifyUrl(sealId: string, baseUrl: string): string {
  if (!baseUrl) throw new Error('getVerifyUrl: baseUrl é obrigatório (o protocolo não tem domínio padrão)')
  return `${baseUrl.replace(/\/+$/, '')}/verify/${sealId}`
}

// ─── Main Seal Function ──────────────────────────────────────────

/**
 * Seal content: hash + sign + create envelope
 */
export async function sealContent(params: {
  text: string
  author: SealAuthor
  privateKey: Uint8Array
  platforms: string[]
  mediaData?: Uint8Array[]
  mediaUrls?: string[]
  mediaCIDs?: string[]
  ipfsCids?: string[]
  ipfsGateways?: string[]
  // pHash dual (off-chain, index-aligned com mediaData/mediaCIDs)
  mediaPerceptualHashes?: string[]
  mediaPerceptualHashes256?: string[]
  // Metadados extraídos server-side (off-chain, índice-aligned)
  mediaMetadata?: unknown[]
  mediaMetadataText?: string[]
  // Fingerprint perceptual de áudio/vídeo (worker dedicado, off-chain, índice-aligned)
  mediaFingerprints?: unknown[]
  // V1.2 · cadeia de custódia nativa (ver SealAncestry). Quando presente,
  // sealIds entram no compositeHash → on-chain via PreservationVault.
  ancestrySealIds?: string[]
  ancestryRootSealId?: string
  contentType?: string
  /** OBRIGATÓRIO. Origem onde este selo poderá ser consultado (ex.: a origin do
   *  cliente que está selando). O protocolo não tem domínio próprio — ver getVerifyUrl. */
  baseUrl: string
  /** Cofre privado já CIFRADO (envelope do vault) — cifre ANTES de chamar. O
   *  protocolo trata isto como blob opaco e não entra no compositeHash. */
  vault?: string
  /** Mídia está cifrada (bytes em mediaUrls = ciphertext TLE1). Selo privado. */
  mediaEncrypted?: boolean
  /** Dados do dispositivo que selou (descritivo; não entra no hash/assinatura). */
  device?: Record<string, unknown>
  /** Identificação da rede do cliente (qualidade da conexão); servidor complementa IP/host/geo. */
  network?: Record<string, unknown>
  /** Assuntos declarados (rede social) — slugs de SEAL_TOPICS, máx. 3. */
  topics?: string[]
}): Promise<SealResult> {
  const { text, author, privateKey, platforms, mediaData, mediaUrls, mediaCIDs, ipfsCids, ipfsGateways, mediaPerceptualHashes, mediaPerceptualHashes256, mediaMetadata, mediaMetadataText, mediaFingerprints, ancestrySealIds, ancestryRootSealId, contentType, baseUrl, vault, mediaEncrypted, device, network, topics } = params

  // 1. Normalize
  const normalized = normalizeContent(text)

  // 2. Hash content
  const contentHash = hashContent(normalized)

  // 3. Hash media (if any)
  const mediaHashes = mediaData ? mediaData.map(hashMedia) : []

  // 4. Composite hash (V1.2 inclui ancestrySealIds quando presente)
  const compositeHash = createCompositeHash(
    contentHash,
    mediaHashes,
    author.pubkey,
    SEAL_BINDING_DOMAIN,
    ancestrySealIds,
  )

  // 5. Sign
  const signature = await signHash(compositeHash, privateKey)

  // 6. Generate IDs
  const sealId = generateSealId(compositeHash)
  const verifyUrl = getVerifyUrl(sealId, baseUrl)

  // 7. Timestamp — CRIT-005 FIX: sempre usar server time, validar range
  const now = new Date()
  const nowUnix = Math.floor(now.getTime() / 1000)
  const timestamp = {
    utc: now.toISOString(),
    unix: nowUnix,
  }

  // 8. Build envelope (V1.1 com chain/version binding — SEAL-CRIT-01 fix)
  const envelope: SealEnvelope = {
    version: SEAL_PROTOCOL_VERSION,
    protocol: 'cøntextTrust',
    contentHash,
    compositeHash,
    signature,
    author,
    timestamp,
    sealId,
    verifyUrl,
    platforms,
    contentType: contentType || undefined,
    vault: vault || undefined,
    device: device && Object.keys(device).length > 0 ? device : undefined,
    network: network && Object.keys(network).length > 0 ? network : undefined,
    content: {
      text: normalized,
      mediaHashes: mediaHashes.length > 0 ? mediaHashes : undefined,
      mediaUrls: mediaUrls && mediaUrls.length > 0 ? mediaUrls : undefined,
      mediaCIDs: mediaCIDs && mediaCIDs.length > 0 ? mediaCIDs : undefined,
      ipfsCids: ipfsCids && ipfsCids.length > 0 ? ipfsCids : undefined,
      ipfsGateways: ipfsGateways && ipfsGateways.length > 0 ? ipfsGateways : undefined,
      mediaPerceptualHashes: mediaPerceptualHashes && mediaPerceptualHashes.length > 0 ? mediaPerceptualHashes : undefined,
      mediaPerceptualHashes256: mediaPerceptualHashes256 && mediaPerceptualHashes256.length > 0 ? mediaPerceptualHashes256 : undefined,
      mediaMetadata: mediaMetadata && mediaMetadata.length > 0 ? mediaMetadata : undefined,
      mediaMetadataText: mediaMetadataText && mediaMetadataText.length > 0 ? mediaMetadataText : undefined,
      // simhash do texto (declarativo) — só quando há texto de fato
      contentSimhash: normalized.trim() ? computeSimhash64(normalized) : undefined,
      // fingerprint perceptual de áudio/vídeo (declarativo) — só quando há
      mediaFingerprints: mediaFingerprints && mediaFingerprints.filter(Boolean).length > 0
        ? mediaFingerprints.filter(Boolean)
        : undefined,
      mediaEncrypted: mediaEncrypted || undefined,
      // Assuntos (rede social): declarativo, portável no envelope. Máx 3 slugs.
      topics: topics && topics.length > 0 ? topics.slice(0, 3) : undefined,
    },
    // V1.2 · cadeia de custódia (só inclui se houver chain declarada)
    ancestry: ancestrySealIds && ancestrySealIds.length > 0
      ? {
          sealIds: ancestrySealIds.slice(), // copy defensivo
          rootSealId: ancestryRootSealId,
          declaredAt: timestamp.utc,
        }
      : undefined,
  }

  return {
    envelope,
    verifyUrl,
    sealId,
  }
}

// ─── Verification ────────────────────────────────────────────────

export interface VerificationResult {
  valid: boolean
  protocolVersion: '1.0' | '1.1' | '1.2' | 'unknown'
  checks: {
    hashMatch: boolean
    signatureValid: boolean
    timestampPresent: boolean
    timestampValid: boolean
    /**
     * @deprecated semanticamente impreciso. Mantido como alias de
     * `authorClaimed` para compatibilidade com consumidores existentes (SDK
     * 0.2.0/0.2.1, /api/verify, /verify/[id]). A verificação da identidade
     * real do autor (DID, WebAuthn, prova on-chain) não é feita aqui —
     * apenas a presença dos campos `author.pubkey` e `author.displayName`.
     * Use `authorClaimed` em código novo.
     */
    authorVerified: boolean
    /**
     * Presença dos campos declarativos de autoria no envelope. NÃO prova que
     * o handle pertence a uma identidade real verificada — só confirma que
     * o envelope carrega pubkey + displayName. Para prova de identidade,
     * use DID/WebAuthn/AT Protocol binding (roadmap V7.6).
     */
    authorClaimed: boolean
    /**
     * P199 (12/ago/2026) · o `sealId` é o prefixo de 16 hex do `compositeHash`
     * (§3.4 da SPEC: "verificadores DEVEM recomputar o compositeHash e conferir
     * o prefixo, nunca confiar no campo"). Até aqui `verifySeal` NÃO conferia:
     * um envelope com `sealId` adulterado retornava `valid: true`, e como o
     * `verifyUrl` é `.../verify/<sealId>`, dava para produzir um selo
     * criptograficamente válido que apontava para o registro de OUTRO selo.
     */
    sealIdMatch: boolean
  }
  /**
   * O envelope está íntegro, mas na fórmula V1.0 de `compositeHash` — aposentada
   * em 1/jun/2026 por não ter binding domain (CRIT-006). NÃO invalida o selo:
   * conteúdo, assinatura e autoria foram conferidos normalmente. Serve para o
   * consumidor exibir "formato aposentado" em vez de tratar como válido comum.
   */
  formatDeprecated: boolean
  envelope: SealEnvelope
}

// CRIT-005 FIX: máximo skew permitido em criação de selo (5 minutos)
export const MAX_TIMESTAMP_SKEW_MS = 5 * 60 * 1000

/**
 * CRIT-006 · fronteira da fórmula V1.0 de `compositeHash` (sem binding domain).
 *
 * ⚖️ O corte vale para a EMISSÃO, nunca para a VERIFICAÇÃO (decisão de
 * 4/ago/2026, P94). Um selo V1.0 criptograficamente íntegro **continua sendo
 * prova**: o conteúdo não mudou, a assinatura confere, o autor confere. O que
 * envelheceu foi o formato, não o fato.
 *
 * A implementação anterior zerava `checks.hashMatch` depois desta data, o que
 * marcava 14 selos públicos e ancorados on-chain como "Rejeitado" — todos
 * íntegros. Num produto cuja missão é prova, negar prova legítima é o pior erro
 * possível. Hoje o motor devolve `formatDeprecated: true` e mantém a validade.
 *
 * ⛔ Emitir em V1.0 já era impossível por construção: `sealContent` só chama
 * `createCompositeHash` com `SEAL_BINDING_DOMAIN`. `createLegacyCompositeHash`
 * existe exclusivamente para RECONHECER envelopes antigos na verificação.
 */
export const LEGACY_V10_CUTOFF = new Date('2026-06-01T00:00:00Z')

/**
 * Verify a sealed content envelope
 */
export async function verifySeal(
  envelope: SealEnvelope,
  originalText?: string
): Promise<VerificationResult> {
  const checks = {
    hashMatch: false,
    signatureValid: false,
    timestampPresent: false,
    timestampValid: false,
    authorVerified: false,
    authorClaimed: false,
    sealIdMatch: false,
  }
  let detectedVersion: '1.0' | '1.1' | '1.2' | 'unknown' = 'unknown'

  // 1. Verify content hash
  // Selo CIFRADO (cifrado/protegido): o texto vive cifrado em content.encBundle e
  // content.text='' no envelope (zero-knowledge). Não dá pra re-hashear o texto aqui —
  // a integridade do conteúdo é provada pelo compositeHash (que inclui o contentHash
  // fixado na selagem) + assinatura Ed25519, validados nos passos 2 e 3. Quando o
  // cliente decifra com a senha, ele recomputa hashContent(text)===contentHash local.
  const isEncryptedContent = envelope.content.contentEncrypted === true
  if (isEncryptedContent) {
    checks.hashMatch = true // provisório — confirmado/derrubado pelo bloco composite abaixo
  } else if (originalText) {
    const normalized = normalizeContent(originalText)
    const recomputedHash = hashContent(normalized)
    checks.hashMatch = recomputedHash === envelope.contentHash
  } else {
    const recomputedHash = hashContent(envelope.content.text)
    checks.hashMatch = recomputedHash === envelope.contentHash
  }

  // 2. Verify composite hash — tenta V1.2 (com ancestry) → V1.1 (binding) → V1.0 (legacy)
  const ancestryIds = envelope.ancestry?.sealIds
  const recomputedCompositeV12 = createCompositeHash(
    envelope.contentHash,
    envelope.content.mediaHashes || [],
    envelope.author.pubkey,
    SEAL_BINDING_DOMAIN,
    ancestryIds,
  )
  const recomputedCompositeV11 = createCompositeHash(
    envelope.contentHash,
    envelope.content.mediaHashes || [],
    envelope.author.pubkey
  )
  const recomputedCompositeV10 = createLegacyCompositeHash(
    envelope.contentHash,
    envelope.content.mediaHashes || [],
    envelope.author.pubkey
  )

  if (recomputedCompositeV12 === envelope.compositeHash) {
    // V1.2 reconhecido. Se ancestry presente → 1.2; senão idêntico a 1.1.
    detectedVersion = ancestryIds && ancestryIds.length > 0 ? '1.2' : '1.1'
    checks.hashMatch = checks.hashMatch && true
  } else if (recomputedCompositeV11 === envelope.compositeHash) {
    detectedVersion = '1.1'
    checks.hashMatch = checks.hashMatch && true
  } else if (recomputedCompositeV10 === envelope.compositeHash) {
    // CRIT-006 · P94 (4/ago/2026): o selo é V1.0 e está ÍNTEGRO. A fórmula está
    // aposentada para emissão, mas prova velha continua sendo prova — o corte
    // não invalida nada aqui. Quem quiser sinalizar o formato usa
    // `formatDeprecated` no resultado; ver LEGACY_V10_CUTOFF.
    detectedVersion = '1.0'
    checks.hashMatch = checks.hashMatch && true
  } else {
    checks.hashMatch = false
  }

  // 3. Verify signature — CRIT-002 (selos): validar formato antes de verificar
  try {
    const sig = envelope.signature
    const pubkeyHex = envelope.author.pubkey
    // Validar formato Ed25519: sig=128 hex chars (64 bytes), pubkey=64 hex chars (32 bytes)
    if (!/^[0-9a-f]{128}$/.test(sig) || !/^[0-9a-f]{64}$/.test(pubkeyHex)) {
      checks.signatureValid = false
    } else {
      const pubkey = hexToBytes(pubkeyHex)
      checks.signatureValid = await verifySignature(
        envelope.compositeHash,
        sig,
        pubkey
      )
    }
  } catch {
    checks.signatureValid = false
  }

  // 4. Timestamp presence + validation
  checks.timestampPresent = !!envelope.timestamp?.utc && !!envelope.timestamp?.unix

  // CRIT-005 · guarda de timestamp FUTURO. Só isso.
  //
  // ⏳ P94 (4/ago/2026): a versão anterior usava `Math.abs(drift) < 1 ano`, o que
  // invalidava qualquer selo com mais de um ano — pelo simples fato de ter
  // envelhecido. É o mesmo erro do CRIT-006 com outra roupa, e ia derrubar
  // sozinho, em abr/2027, os mesmos 14 selos que este commit acabou de resgatar.
  // Prova não vence. Selo antigo é o caso NORMAL de um protocolo de proveniência:
  // quanto mais velho o registro, mais valor ele tem.
  //
  // Timestamp no FUTURO continua suspeito: ninguém sela o que ainda não escreveu.
  // A tolerância é a mesma da criação (MAX_TIMESTAMP_SKEW_MS), para absorver
  // relógio dessincronizado do cliente.
  if (checks.timestampPresent && envelope.timestamp.unix) {
    const sealTimeMs = envelope.timestamp.unix * 1000
    const adiantamento = sealTimeMs - Date.now()
    checks.timestampValid = adiantamento <= MAX_TIMESTAMP_SKEW_MS
  }

  // 5. Author — apenas presença dos campos declarativos (claim, não prova)
  //    AUDIT-EXTERNO 2026-04-21: renomeado de "authorVerified" para "authorClaimed"
  //    por ser semanticamente correto. Campo legado "authorVerified" mantido como
  //    alias pra não quebrar SDK/consumidores até V7.6 trazer DID/WebAuthn.
  // Selo cifrado/protegido: displayName fica '' no envelope (vai cifrado no encBundle).
  // authorClaimed exige só a pubkey (material da assinatura); o nome é revelado no
  // cliente após decifrar. Selo normal: mantém a checagem de pubkey + displayName.
  checks.authorClaimed = isEncryptedContent
    ? !!envelope.author?.pubkey
    : (!!envelope.author?.pubkey && !!envelope.author?.displayName)
  checks.authorVerified = checks.authorClaimed // alias legado

  // 6. sealId — P199 (§3.4). O `sealId` DEVE ser um PREFIXO do compositeHash.
  //    Quando `hashMatch` é true, `envelope.compositeHash` é o valor recomputado
  //    (foi o que casou uma das três fórmulas acima), então conferir o prefixo
  //    contra ele é conferir contra o hash recomputado — o que a SPEC exige.
  //
  //    ⚠️ NÃO é igualdade com `generateSealId` (16 hex): o CRIT-003 aumentou o
  //    sealId de 8 para 16 chars na V7.7, e os selos V1.0 anteriores têm sealId
  //    de 8 hex — legítimos, ancorados, prova. Exigir 16 exatos reprovaria prova
  //    velha, que é o pior erro num protocolo de proveniência (a mesma lição do
  //    P94). O invariante que PEGA o ataque é ser prefixo do MESMO compositeHash:
  //    um sealId trocado para apontar o registro de outro selo não é prefixo
  //    deste, e cai aqui. A emissão nova continua exigindo 16 no gate estrito do
  //    app (`validateCurrentSealEmission`); aqui é a verificação, que acolhe a
  //    história.
  //    ⚖️ Quando `hashMatch` é false o compositeHash não é confiável, mas aí
  //    `valid` já cai por hashMatch; este check nunca "resgata" um selo.
  checks.sealIdMatch =
    typeof envelope.sealId === 'string' &&
    /^[0-9a-f]{8,16}$/.test(envelope.sealId) &&
    typeof envelope.compositeHash === 'string' &&
    envelope.compositeHash.startsWith(envelope.sealId)

  const valid =
    checks.hashMatch &&
    checks.signatureValid &&
    checks.timestampPresent &&
    checks.timestampValid &&
    checks.authorClaimed &&
    checks.sealIdMatch

  // Formato aposentado ≠ prova inválida. Só marca quando o envelope de fato
  // conferiu na fórmula V1.0 e a data já passou do corte (ver LEGACY_V10_CUTOFF).
  const formatDeprecated = detectedVersion === '1.0' && new Date() > LEGACY_V10_CUTOFF

  return {
    valid,
    protocolVersion: detectedVersion,
    checks,
    formatDeprecated,
    envelope,
  }
}

// ─── Utils ───────────────────────────────────────────────────────

/**
 * hex → bytes.
 *
 * ⚠️ Reintroduzido em 28/jul/2026. A extração do pacote (commit 290f355)
 * trouxe as chamadas mas deixou o helper para trás: `hexToBytes` era uma
 * função LOCAL de `seal-engine.ts` no app, não um import de @noble.
 * O pacote publicado teria lançado `ReferenceError` em `verifySeal`
 * (verificação de assinatura), `generateKeypair` e na checagem de coautor —
 * ou seja, quebrado no caminho mais importante que ele tem.
 *
 * Só apareceu ao rodar `tsc` de verdade sobre o pacote. Os 12 testes de
 * conformidade NÃO pegaram porque, por desenho, eles reimplementam a SPEC do
 * zero sem importar o pacote — provam que a SPEC está certa, não que o
 * PACOTE funciona. Por isso agora existe também `smoke.test.mjs`, que
 * importa o pacote de verdade.
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}
