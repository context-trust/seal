# Especificação do Selo cøntextTrust — V1.2

**Status:** normativa · **Versão do selo:** `1.2.0` · **Data:** 27/jul/2026
**Licença:** Apache-2.0

Este documento define como um selo cøntextTrust é produzido e verificado. Ele foi
derivado da implementação **que está em produção** e validado contra selos reais
já assinados (ver §9). Uma implementação independente que siga este documento
produz e verifica selos interoperáveis, **sem precisar de autorização, servidor
ou banco de dados de ninguém**.

As palavras **DEVE**, **NÃO DEVE** e **PODE** têm o sentido usual do RFC 2119.

---

## 1. Modelo

Um **selo** é uma afirmação assinada de que um conteúdo existia, com uma
determinada autoria declarada, antes de um certo instante.

O selo **NÃO** é uma afirmação sobre identidade civil, sobre veracidade do
conteúdo, nem sobre onde o selo foi criado. Ver §8.

Três camadas independentes:

| Camada | O que prova | Depende de |
|---|---|---|
| **Selo** (esta spec) | integridade do conteúdo + posse da chave | nada |
| **Âncora** (on-chain) | anterioridade temporal | uma blockchain pública |
| **Identidade** (fora do escopo) | quem é o dono da chave | um emissor de atestação |

---

## 2. Normalização canônica

Antes de qualquer hash, o texto **DEVE** ser normalizado:

1. Normalização Unicode **NFC**
2. Remoção de espaços em branco no **fim de cada linha**
3. Remoção de espaços em branco no **fim do texto inteiro**

```
normalize(t) = rstrip( join( map(rstrip, split(NFC(t), "\n")), "\n" ) )
```

Quebras de linha internas, espaços no início de linha e linhas vazias no meio
são **preservados** — são conteúdo.

---

## 3. Hashes

Função de hash: **BLAKE3-256**, saída em hexadecimal minúsculo (64 chars).

### 3.1 contentHash
```
contentHash = BLAKE3-256( utf8( normalize(text) ) )
```

### 3.2 mediaHashes
Um por arquivo, sobre os **bytes originais** (não sobre o arquivo cifrado ou
transcodificado):
```
mediaHash[i] = BLAKE3-256( bytes[i] )
```

### 3.3 compositeHash — o núcleo da prova
```
parts = [ contentHash ] ++ sort(mediaHashes) ++ [ author.pubkey, bindingDomain ]
se ancestry.sealIds não for vazio:
    parts ++= [ "ancestry:" + join(sort(ancestry.sealIds), ",") ]

compositeHash = BLAKE3-256( utf8( join(parts, ":") ) )
```

- `sort` é ordenação lexicográfica dos hexadecimais. Torna o hash independente
  da ordem de upload.
- `bindingDomain` **DEVE** ser exatamente:
  `cøntextTrust:polygon-mainnet:137`
  (com o **ø** U+00F8; em UTF-8: `C3 B8`).
  Ele amarra a assinatura a uma rede e versão específicas. Trocar de chain
  **invalida toda assinatura existente** — é intencional, previne replay
  cross-chain. Uma implementação **NÃO DEVE** parametrizar isto sem publicar
  uma nova versão do selo.
- O prefixo literal `ancestry:` separa domínios semânticos.

### 3.4 sealId
```
sealId = compositeHash[0..16)     // 16 primeiros chars hex
```
`sealId` é um **prefixo**, não um hash independente. Verificadores **DEVEM**
recomputar o `compositeHash` e conferir o prefixo, nunca confiar no campo.

---

## 4. O que entra e o que NÃO entra na prova

**Entra** (alterar invalida o selo): `contentHash`, `content.mediaHashes`,
`author.pubkey`, `bindingDomain`, `ancestry.sealIds`.

**NÃO entra** (metadado descritivo; alterar **não** invalida nada):

> `verifyUrl` · `platforms` · `contentType` · `vault` · `device` · `network` ·
> `content.topics` · `content.mediaUrls` · `content.mediaCIDs` ·
> `content.ipfsCids` · `content.ipfsGateways` · `mediaPerceptualHashes` ·
> `mediaPerceptualHashes256` · `contentSimhash` · `mediaFingerprints` ·
> `mediaMetadata` · `mediaMetadataText` · `author.displayName` · `author.handle`

⚠️ Consequência que **DEVE** ser comunicada ao usuário final: um selo **não
prova** em que site foi criado, nem qual o nome do autor. Prova a posse da
chave. Interfaces **NÃO DEVEM** apresentar campos desta lista como prova.

### 4.1 `mediaPerceptualHashes` costuma vir vazio, e isso é esperado

O hash perceptual só existe quando o cliente **consegue decodificar a imagem**
para calculá-lo. Formatos que o navegador não decodifica no caminho de selagem
(HEIC, PDF, áudio, vídeo) produzem a entrada **vazia**, e medição em produção de
15/ago/2026 mostra que isso é a maioria: **3 de 13** selos com mídia tinham hash
perceptual, e todos os três eram imagens comuns decodificadas pelo cliente.

Isso **não** afeta a prova: a integridade da mídia é garantida pelo
`mediaHashes` (BLAKE3 sobre os bytes originais), que entra no `compositeHash`. O
hash perceptual serve para **reconhecer parecença** depois de recompressão ou
recorte, e é recurso auxiliar.

Implementações **DEVERIAM** distinguir "não calculado" de "calculado e vazio",
usando `null` em vez de string vazia, para o auditor não interpretar campo vazio
como falha de captura.

⚠️ A recomendação vale para quem **emite**, e só para selos novos. Um verificador
**NÃO PODE** trocar `""` por `null` ao devolver um envelope já assinado: o
`compositeHash` é calculado sobre o JSON canônico, então reescrever qualquer
campo na saída faria a prova deixar de fechar para quem recomputasse a partir
dela. O campo vazio de um selo antigo é o que foi assinado, e permanece assim
para sempre. É a diferença entre corrigir o emissor e adulterar o registro.

---

## 5. Assinatura

Algoritmo: **Ed25519** (RFC 8032).

```
signature = Ed25519.sign( privateKey, utf8( compositeHash ) )
```

⚠️ **Armadilha de implementação.** A mensagem assinada é a **string
hexadecimal** do `compositeHash` (64 bytes ASCII), **não** os 32 bytes que ela
representa. Assinar os bytes produz uma assinatura que falha em 100% dos selos.

Formatos: `signature` = 128 chars hex; `author.pubkey` = 64 chars hex.
Um verificador **DEVE** validar esses formatos antes de chamar a curva.

⚠️ **Segunda armadilha — aceitação de operador NÃO é prova.** Um endpoint de
emissão operado por terceiros (por exemplo, o `POST /api/seal` da trustLayers)
valida formato, janela de horário e quota — **não** verifica a assinatura na
ingestão. A conferência criptográfica acontece na **verificação** (§7), que
qualquer pessoa executa com o envelope, sem o operador. Implicação normativa:
uma implementação **NÃO DEVE** tratar "o operador aceitou" como evidência de
autenticidade, e **NÃO DEVE** depender do operador para verificar. O envelope
é a prova; o operador é só transporte.

### 5.1 Vetor de teste da assinatura

Vetor determinístico para conferir uma reimplementação. Chave privada **de
teste** (nunca usar em produção): os 32 bytes `0x01 0x02 … 0x20`.

```jsonc
{
  "privateKey":   "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "pubkey":       "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
  "texto":        "prova não é promessa",
  "contentHash":  "95cc2529f35c0099167f63d441e838d2a8832ec17fe64552b5fe075cf6e11a4f",
  "compositeHash":"34e2b8e452a3f6d4b2709fca58c36544ec0b470ed76e17d940bb881f41bb6b7c",
  "sealId":       "34e2b8e452a3f6d4",
  "signature":    "c8f77d04a649a3a2264ec0cbd3f9982d3688c9fb0b3b6570c6bd078d0bd663918fa476f741c03b46d6c39b4b1916518b36eb0a00ff6c8793e944b66b2385d10b"
}
```

Conferências, nesta ordem:

1. `verify( signature, utf8(compositeHash), pubkey )` → **true**.
2. Assinar os **32 bytes** de `compositeHash` com a mesma chave e verificar
   contra este vetor → **false**. Se a sua implementação devolve *true* aqui,
   ela caiu na armadilha da §5 e falhará em 100% dos selos reais.
3. `contentHash` recomputado de `texto` (normalização §2 + hash §3.1) deve
   bater byte a byte — se não bater, o erro está ANTES da assinatura.

---

## 6. Envelope

```jsonc
{
  "version": "1.2.0",
  "protocol": "cøntextTrust",
  "contentHash":   "<64 hex>",
  "compositeHash": "<64 hex>",
  "signature":     "<128 hex>",
  "author":  { "pubkey": "<64 hex>", "displayName": "…", "handle": "…" },
  "timestamp": { "utc": "<ISO-8601>", "unix": 1234567890 },
  "sealId":    "<16 hex>",
  "verifyUrl": "https://…/verify/<sealId>",   // metadado (§4)
  "platforms": [],
  "content": {
    "text": "…",
    "mediaHashes": ["<64 hex>", "…"]
    // demais campos: metadados (§4)
  },
  "ancestry": {                                // opcional, V1.2
    "sealIds": ["<16 hex>", "…"],
    "rootSealId": "<16 hex>",
    "declaredAt": "<ISO-8601>"
  }
}
```

O envelope é **auto-contido**: tudo que um verificador precisa para recomputar
está dentro dele. Esta é uma propriedade **normativa** — uma implementação
**NÃO DEVE** exigir consulta externa para verificar §7.1–§7.3.

### 6.1 Envelope cifrado (modalidade Cofre)

Na modalidade Cofre, o **conteúdo** viaja cifrado; a prova (§3–§5) continua
pública e verificável — o que se cifra é o texto/mídia, nunca os hashes.
O formato é texto com campos separados por `:`, despachado pelo **prefixo**:

| prefixo | KDF | cifra | uso |
|---|---|---|---|
| `VAULT_A2` | **Argon2id** `m=19456 KiB · t=2 · p=1` | AES-256-GCM | atual, texto |
| `VAULT_V1` | PBKDF2-SHA256, 250.000 iterações | AES-256-GCM | legado, texto |
| `TLE2` | mesmo Argon2id | AES-256-GCM | atual, mídia binária |
| `TLE1` | mesmo PBKDF2 | AES-256-GCM | legado, mídia binária |

```
VAULT_A2:<m>:<t>:<p>:<salt_b64url>:<iv_b64url>:<ciphertext_b64url>
VAULT_V1:<salt_b64url>:<iv_b64url>:<ciphertext_b64url>
```

Derivação: `chave = KDF( senha_do_usuário, salt )` → AES-256-GCM com o `iv`
do envelope. Os **parâmetros do Argon2id viajam no próprio envelope** — é isso
que permite endurecer o custo no futuro sem quebrar cofres antigos: o leitor
usa os parâmetros gravados, não os atuais.

Regras normativas:

- Uma implementação que **escreve** DEVE usar apenas os formatos atuais
  (`VAULT_A2`/`TLE2`).
- Uma implementação que **lê** DEVE aceitar os quatro prefixos **para
  sempre** — envelope legado é conteúdo de usuário, e conteúdo de usuário
  não expira porque o software evoluiu.
- A senha nunca sai do cliente; o servidor armazena e serve o envelope
  **opaco**. Perder a senha = perder o conteúdo, por desenho. Não há
  recuperação — e um implementador NÃO DEVE adicionar uma, porque qualquer
  porta de recuperação é uma porta de leitura.

---

## 7. Verificação

Um verificador **DEVE** executar, em ordem:

1. **Integridade do conteúdo** — recomputar `contentHash` a partir de
   `content.text` normalizado e comparar. Se `content.contentEncrypted` for
   `true`, este passo é **pulado** (o texto é ciphertext); a integridade fica
   provada pelo passo 2.
2. **compositeHash** — recomputar conforme §3.3 e comparar. Verificadores
   **DEVEM** aceitar as variantes legadas (§7.4).
3. **Assinatura** — verificar conforme §5.
4. **Timestamp** — presente e dentro de tolerância. Deriva futura máxima
   recomendada: 5 min; deriva passada implausível (> 1 ano) **DEVE** ser
   sinalizada.
5. **Âncora** *(opcional, quando houver)* — ver §7.5.

Um selo **só é válido** se 1–3 passarem. Os passos 4–5 qualificam a prova
temporal, não a autoria.

### 7.4 Compatibilidade com versões anteriores
| Versão | compositeHash | Situação |
|---|---|---|
| **V1.2** | com `ancestry` | atual |
| **V1.1** | sem `ancestry` | válida (produz hash idêntico a V1.2 sem linhagem) |
| **V1.0** | sem `bindingDomain` | **rejeitada** após 2026-06-01 (vulnerável a replay) |

### 7.5 Prova de inclusão on-chain
Selos **PODEM** ser ancorados em lote via árvore Merkle:

```
folha = keccak256( keccak256( bytes32(compositeHash) ) )   // duplo hash, padrão OpenZeppelin
nó    = keccak256( concat( sort(a, b) ) )                  // pares comutativos
```
A raiz resultante **DEVE** ser igual à emitida no evento on-chain. Ler a raiz de
um nó público qualquer é suficiente — o verificador **NÃO DEVE** depender de um
endpoint específico.

---

## 8. O que um selo NÃO prova

Declaração normativa, para evitar uso indevido:

1. **Não prova identidade civil.** Prova posse de uma chave. Ligar chave a
   pessoa é responsabilidade de uma camada de atestação externa.
2. **Não prova veracidade.** Um conteúdo falso pode ser selado com perfeição.
3. **Não prova origem.** `verifyUrl` não é assinado (§4).
4. **Não prova anterioridade sem âncora.** O `timestamp` é auto-declarado; só a
   inclusão on-chain (§7.5) dá data verificável por terceiros.

---

## 9. Conformidade

Uma implementação é **conforme** se reproduz os vetores de `test/` deste pacote.
Os vetores são selos **reais de produção**, incluindo o caminho V1.2 com
linhagem e mídia. A suíte verifica `contentHash`, `compositeHash`, assinatura e
derivação do `sealId`.

Foi assim que esta spec foi validada: uma reimplementação escrita do zero, sem
consultar o código de origem, reproduziu selos reais byte a byte.

---

## 10. Histórico


| 2026-08-05 | Editorial (sem quebra): §5 ganha a segunda armadilha (aceitação de operador não é prova) e o vetor de teste §5.1 com prova negativa; §6.1 documenta o envelope cifrado do Cofre (P31 + P32) |

| Versão | Data | Mudança |
|---|---|---|
| 1.0 | abr/2026 | inicial · sem `bindingDomain` |
| 1.1 | 15/abr/2026 | + `bindingDomain` (anti-replay cross-chain) |
| 1.2 | 27/mai/2026 | + `ancestry` no compositeHash (cadeia de custódia) |
| — | 27/jul/2026 | **primeira redação normativa** (este documento) |
| — | 15/ago/2026 | + §11 (mapa de versões), a pedido de auditoria externa |

---

## 11. Mapa de versões · o que cada número versiona

Quem audita o protocolo encontra **quatro numerações diferentes** ao mesmo tempo e, sem esta tabela, a impressão é de contradição. Elas versionam coisas distintas e evoluem em ritmos distintos.

⚠️ A coluna da direita diz **onde ler o número agora**, e não qual ele era no dia em que
esta seção foi escrita. A primeira versão desta tabela trazia a biblioteca como `1.4.0` e
envelheceu em dois dias, dentro da seção criada justamente para acabar com confusão de
número. Número copiado à mão para dentro de documento é defeito com data marcada.

| Número | O que versiona | Onde se lê **agora** |
|---|---|---|
| **Protocolo** (1.0 / 1.1 / 1.2) | a **fórmula do `compositeHash`** definida nesta SPEC | campo `protocolVersion` na resposta da verificação; vale `1.1` ou `1.2` conforme o selo tenha linhagem |
| **Envelope** (`version`) | o **formato do arquivo** de envelope emitido pelo app | campo `version` dentro do próprio envelope |
| **Biblioteca** (npm) | a implementação de referência `@contexttrust/seal` | `npm view @contexttrust/seal version`, ou `dist-tags.latest` em `https://registry.npmjs.org/@contexttrust/seal` |
| **Contrato** | a implementação on-chain de cada contrato | `version()` no contrato, lido por `eth_call` (ver `CONTRATOS.md` no espelho público) |

### 11.1 Por que um envelope `1.2.0` é verificado como protocolo `1.1`

Não é divergência, é a regra de §7.4 aplicada: **1.1 e 1.2 diferem apenas pelo campo `ancestry`**. Um selo sem linhagem produz **hash idêntico** nas duas fórmulas, então o verificador informa a fórmula mais antiga que fecha, que é `1.1`. Um selo com linhagem só fecha em `1.2` e é informado como `1.2`.

Implementações **DEVEM** reportar a fórmula que casou, não a versão declarada no envelope. Interfaces **DEVERIAM** explicar a equivalência quando as duas divergem, porque quem lê só o JSON não tem como saber.

### 11.2 Por que `bindingDomain` não aparece no envelope

Ele entra no **cálculo** do `compositeHash` (§3) como constante da rede, e não é guardado como campo do envelope. Recomputar sem ele não fecha o hash, então sua ausência no JSON não é omissão: é o valor estar embutido na prova, e não no papel.
