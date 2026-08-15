/**
 * smoke.test.mjs — o teste que IMPORTA o pacote.
 *
 * ── Por que ele existe (28/jul/2026) ────────────────────────────────────
 * `conformance.test.mjs` é deliberadamente independente: reimplementa a
 * SPEC.md do zero, só com @noble, sem importar `@contexttrust/seal`. Isso é
 * uma virtude — prova que a SPEC é implementável por um terceiro e que os
 * selos de produção batem com ela.
 *
 * Mas tinha um ponto cego: **ele nunca executa o pacote.** Dois defeitos
 * reais passaram por ele, os dois só descobertos ao compilar e RODAR:
 *
 *   1. `hexToBytes` era função LOCAL do `seal-engine.ts` do app e ficou para
 *      trás na extração. O pacote lançaria `ReferenceError` dentro de
 *      `verifySignature` / `verifySeal` / `importKeyPair` — o caminho mais
 *      importante que ele tem.
 *   2. `import ... from './simhash'` sem extensão. O ESM do Node resolve o
 *      caminho literal ⇒ `ERR_MODULE_NOT_FOUND` no primeiro require.
 *
 * Os 12 testes de conformidade ficaram verdes o tempo todo nos dois casos.
 * Lição: teste que valida a ESPECIFICAÇÃO não valida o ARTEFATO.
 *
 * Este arquivo importa `dist/` — exatamente o que vai pro npm.
 * Rodar: npm install && npm run build && npm test
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const { vectors, bindingDomain } = JSON.parse(
  readFileSync(join(here, 'vectors.json'), 'utf8'),
)

// Importa o ARTEFATO — não uma reimplementação.
const pkg = await import('../dist/index.js')

test('o pacote carrega e expõe a superfície pública da SPEC', () => {
  for (const nome of [
    'verifySignature', 'createCompositeHash', 'hashContent',
    'normalizeContent', 'getVerifyUrl', 'generateKeyPair', 'importKeyPair',
  ]) {
    assert.equal(typeof pkg[nome], 'function', `faltou export: ${nome}`)
  }
  assert.equal(pkg.SEAL_BINDING_DOMAIN, bindingDomain,
    'o domínio de binding do pacote divergiu do gravado nos vetores')
})

test('hashContent reproduz o contentHash dos selos REAIS de produção', async () => {
  for (const v of vectors) {
    const got = await pkg.hashContent(pkg.normalizeContent(v.text))
    assert.equal(got, v.contentHash, `contentHash divergiu em ${v.nome}`)
  }
})

test('createCompositeHash reproduz o compositeHash dos selos REAIS', async () => {
  for (const v of vectors) {
    // ⚠️ ORDEM: (contentHash, mediaHashes, pubkey, bindingDomain, ancestry).
    // `bindingDomain` é o 4º — passar a linhagem ali dentro produz um hash
    // silenciosamente errado. Foi o que este teste fez na 1ª versão.
    const got = await pkg.createCompositeHash(
      v.contentHash, v.mediaHashes ?? [], v.pubkey,
      pkg.SEAL_BINDING_DOMAIN, v.ancestrySealIds ?? [],
    )
    assert.equal(got, v.compositeHash, `compositeHash divergiu em ${v.nome}`)
  }
})

// ─── Estes dois são os que pegariam o bug do hexToBytes ────────────────
test('verifySignature ACEITA a assinatura real de cada selo de produção', async () => {
  let checados = 0
  for (const v of vectors) {
    if (!v.signature) continue
    const ok = await pkg.verifySignature(v.compositeHash, v.signature, v.pubkey)
    assert.equal(ok, true, `assinatura do selo ${v.sealId} (${v.nome}) deveria validar`)
    checados++
  }
  assert.ok(checados > 0, 'nenhum vetor com assinatura foi exercitado')
})

test('verifySignature REJEITA assinatura adulterada', async () => {
  const v = vectors.find(x => x.signature)
  // Vira o último nibble: segue hex bem-formado, cripto inválida.
  const ultimo = v.signature.slice(-1)
  const adulterada = v.signature.slice(0, -1) + (ultimo === '0' ? '1' : '0')
  const ok = await pkg.verifySignature(v.compositeHash, adulterada, v.pubkey)
  assert.equal(ok, false, 'assinatura adulterada NÃO pode validar')
})

test('importKeyPair aceita hex e faz o round-trip com exportKeyPair', async () => {
  // Também depende de hexToBytes.
  const kp = await pkg.generateKeyPair()
  const hex = await pkg.exportKeyPair(kp)
  const devolta = await pkg.importKeyPair(hex)
  const hex2 = await pkg.exportKeyPair(devolta)
  assert.deepEqual(hex2, hex, 'round-trip de chave não fechou')
})

test('getVerifyUrl exige baseUrl — o protocolo não tem domínio padrão', () => {
  assert.throws(() => pkg.getVerifyUrl('abc123', ''), /baseUrl/i)
  assert.equal(
    pkg.getVerifyUrl('abc123', 'https://exemplo.test/'),
    'https://exemplo.test/verify/abc123',
  )
})
