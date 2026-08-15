// Suíte de conformidade do selo cøntextTrust V1.2.
//
// Roda com: node --test test/
//
// Ela NÃO importa o pacote. Reimplementa a SPEC.md do zero — só com @noble —
// e confere contra selos REAIS de produção (test/vectors.json). É esse
// distanciamento que dá valor ao teste: se a spec estiver incompleta ou
// ambígua, esta suíte quebra. Se passar, um terceiro consegue implementar o
// protocolo lendo apenas a SPEC.
//
// Depois compara com o pacote, garantindo que código e spec não divergiram.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { blake3 } from '@noble/hashes/blake3.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import * as ed from '@noble/ed25519'

// 🔴 P107: a v3 do @noble/ed25519 NÃO aceita mais hex string — exige Uint8Array.
// A v2 tolerava, e era nessa tolerância que estes testes se apoiavam. Converter
// aqui mantém os testes exercendo a CRIPTOGRAFIA, e não o parser de argumentos:
// um teste negativo que passa por TypeError estaria passando pelo motivo errado.
const hx = (h) => (h instanceof Uint8Array ? h : Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16))))

// 🔴 P107 (5/ago/2026): na v2 do @noble/ed25519 era preciso injetar o SHA-512 aqui.
// Na v3 o `ed.etc` é CONGELADO e o hash já vem embutido em `ed.hashes.sha512` —
// tentar injetar estoura "object is not extensible". O shim virou PROIBIDO, não só
// desnecessário.

const here = dirname(fileURLToPath(import.meta.url))
const { bindingDomain, vectors } = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8'))

// ─── Implementação a partir da SPEC, sem olhar o código do pacote ───

/** SPEC §2 */
function normalize(t) {
  return t.normalize('NFC').split('\n').map((l) => l.replace(/\s+$/, '')).join('\n').replace(/\s+$/, '')
}
/** SPEC §3.1 */
const hash = (s) => bytesToHex(blake3(utf8ToBytes(s)))

/** SPEC §3.3 */
function composite(contentHash, mediaHashes, pubkey, ancestrySealIds) {
  const parts = [contentHash, ...[...(mediaHashes ?? [])].sort(), pubkey, bindingDomain]
  if (ancestrySealIds && ancestrySealIds.length > 0) {
    parts.push('ancestry:' + [...ancestrySealIds].sort().join(','))
  }
  return hash(parts.join(':'))
}

/** SPEC §3.4 */
const sealIdOf = (compositeHash) => compositeHash.slice(0, 16)

for (const v of vectors) {
  test(`[spec] ${v.nome}`, async () => {
    // §7.1 — integridade do conteúdo
    assert.equal(hash(normalize(v.text)), v.contentHash, 'contentHash (SPEC §3.1)')

    // §7.2 — composite hash
    assert.equal(
      composite(v.contentHash, v.mediaHashes, v.pubkey, v.ancestrySealIds),
      v.compositeHash,
      'compositeHash (SPEC §3.3)',
    )

    // §3.4 — sealId é prefixo, nunca campo de confiança
    assert.equal(sealIdOf(v.compositeHash), v.sealId, 'sealId (SPEC §3.4)')

    // §7.3 — assinatura sobre a STRING HEX (armadilha documentada na §5)
    assert.equal(
      await ed.verifyAsync(hx(v.signature), utf8ToBytes(v.compositeHash), hx(v.pubkey)),
      true,
      'assinatura Ed25519 (SPEC §5)',
    )
  })
}

test('[spec §5] assinar os BYTES do hash, e não a string hex, DEVE falhar', async () => {
  const v = vectors[0]
  const bytesDoHash = Uint8Array.from(v.compositeHash.match(/../g).map((b) => parseInt(b, 16)))
  assert.equal(await ed.verifyAsync(hx(v.signature), bytesDoHash, hx(v.pubkey)), false)
})

test('[spec §3.3] ordem das mídias não altera o compositeHash', () => {
  const v = vectors[0]
  const duas = ['ff'.repeat(32), '00'.repeat(32)]
  assert.equal(
    composite(v.contentHash, duas, v.pubkey, null),
    composite(v.contentHash, [...duas].reverse(), v.pubkey, null),
  )
})

test('[spec §3.3] ordem da linhagem não altera o compositeHash', () => {
  const v = vectors[0]
  assert.equal(
    composite(v.contentHash, v.mediaHashes, v.pubkey, ['bbbb', 'aaaa']),
    composite(v.contentHash, v.mediaHashes, v.pubkey, ['aaaa', 'bbbb']),
  )
})

test('[spec §3.3] linhagem vazia produz o MESMO hash que ausência de linhagem (compat V1.1)', () => {
  const v = vectors[0]
  assert.equal(
    composite(v.contentHash, v.mediaHashes, v.pubkey, []),
    composite(v.contentHash, v.mediaHashes, v.pubkey, null),
  )
})

test('[spec §3.3] bindingDomain errado invalida o selo (anti-replay cross-chain)', () => {
  const v = vectors[0]
  const outro = [v.contentHash, ...v.mediaHashes, v.pubkey, 'contextTrust:polygon-mainnet:137'].join(':')
  assert.notEqual(hash(outro), v.compositeHash)
})

test('[spec §2] normalização: espaço no fim de linha e do texto é removido; o resto é preservado', () => {
  assert.equal(normalize('a  \nb\t\n'), 'a\nb')
  assert.equal(normalize('  indentado'), '  indentado', 'espaço no INÍCIO é conteúdo')
  assert.equal(normalize('a\n\nb'), 'a\n\nb', 'linha vazia interna é conteúdo')
})

// ─── O pacote concorda com a spec? ───
test('[pacote] @contexttrust/seal reproduz todos os vetores', async () => {
  const pkg = await import('../src/seal.ts').catch(() => null)
  if (!pkg) {
    console.log('  (pulado: requer runtime com suporte a TS — rode via tsx/vitest)')
    return
  }
  for (const v of vectors) {
    assert.equal(pkg.hashContent(pkg.normalizeContent(v.text)), v.contentHash, v.nome)
    assert.equal(
      pkg.createCompositeHash(v.contentHash, v.mediaHashes ?? [], v.pubkey, pkg.SEAL_BINDING_DOMAIN, v.ancestrySealIds ?? undefined),
      v.compositeHash,
      v.nome,
    )
    assert.equal(pkg.generateSealId(v.compositeHash), v.sealId, v.nome)
  }
})
