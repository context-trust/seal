# Contratos do cøntextTrust na Polygon mainnet

Este arquivo existe para que **"os contratos estão verificados" seja uma afirmação que
você confere sozinho**, sem pedir nada a nós. Ele traz os endereços de produção, o estado
de verificação de cada um e os comandos para reproduzir cada linha.

Rede: **Polygon mainnet (chainId 137)**. Compilador: `0.8.28+commit.7893614a`.

## Os oito endereços

Sete são **proxies UUPS**: o endereço estável guarda o estado e delega para uma
implementação que pode ser trocada. Quem verifica precisa olhar a **implementação**, não o
proxy — é o passo que a maioria pula, e foi onde estava o nosso defeito de 15/ago/2026.

| Contrato | Endereço (o que você chama) | Implementação hoje | Verificação |
|---|---|---|---|
| ContentRegistry | `0x70a656FDcf9Cab966a5C9c283563a22f3D813c32` | `0xCb7D14A2573a87390B475F3fdbcbAb577658a183` · **ContentRegistryV3** | `exact_match` |
| PreservationVault | `0x40F152A25E2B7F0d55Ea5A76C49BCD8E03b28852` | `0x041385b9a136Cf393F3727b1F3082E6dD873bb02` · **PreservationVaultV2** | `match` |
| HourlyAnchor | `0x1B627fF9d6A341b27bD24207a3F6C8F9E8c1CDE9` | `0xa6D00dbBC96531282E60460F6f37bA2BEc0Cb716` · **HourlyAnchor** | `exact_match` |
| MirrorAnchor | `0xD950cDdc624A9C16D6018B8DF95dfE9ED0729e38` | deploy direto, sem proxy | `exact_match` |
| TrustSealNFT | `0x751D70C3ac2b60A13603f1D61a480edcB82f563e` | `0x22633274DfF0f5D76134BcAbB6d1A62f7456B438` · **TrustSealNFT** | `exact_match` |
| ValidatorRegistry | `0xeD9941279ce8949abEFE25C18b1E227d2012a63c` | `0x1CDa41848642Eb207D4a98666a4D1066a222c0AB` · **ValidatorRegistry** | `exact_match` |
| DisputeResolution | `0x7350B4E6fb59FeC74E736CB9eEFd13aF8800C1F4` | `0xAe0f20DBFD1C363798A8804b3f7A533114CCc710` · **DisputeResolution** | `match` |
| CTXToken | `0xB39a061E3776D8a0120Aaa3E20A1a1A93766afe1` | `0xa0881952b6dDEB7f938F1289239B981e5816C579` · **CTXToken** | `exact_match` |

Medido em 16 de agosto de 2026. O estado de verificação não regride sozinho, mas a
**implementação muda a cada upgrade** — por isso o comando abaixo lê o endereço da
implementação na hora, em vez de confiar nesta tabela.

### `exact_match` e `match` não são a mesma coisa

Seis contratos são `exact_match` e dois são `match`. Nos dois casos o **bytecode em
execução confere com o código-fonte publicado**, que é o que importa para auditar. A
diferença é o hash de metadados embutido no fim do bytecode: em `match` ele não é
idêntico, o que acontece quando o artefato foi compilado noutro ambiente. Dizemos os dois
nomes em vez de arredondar para o mais bonito.

## Como reproduzir, um comando por vez

**1. O endereço existe e tem código.** Zero aqui significa endereço morto, e é o primeiro
teste porque um `eth_getLogs` sem eventos num endereço vazio parece silêncio e é ausência.

```bash
curl -s https://polygon-bor-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0x70a656FDcf9Cab966a5C9c283563a22f3D813c32","latest"]}'
```

**2. Qual implementação o proxy usa agora.** O endereço vive no slot ERC-1967
`0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`; os últimos 40 hex da
resposta são o endereço.

```bash
curl -s https://polygon-bor-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":["0x70a656FDcf9Cab966a5C9c283563a22f3D813c32","0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc","latest"]}'
```

**3. Essa implementação está verificada, e com que nome.** Sem chave de API.

```bash
curl -s "https://sourcify.dev/server/v2/contract/137/0xCb7D14A2573a87390B475F3fdbcbAb577658a183?fields=compilation"
```

**4. As constantes que os nossos documentos afirmam.** Cada seletor abaixo são os quatro
primeiros bytes do keccak-256 da assinatura, e a resposta vem em hexadecimal.

| Leitura | Contrato | Seletor | Valor em 16/ago/2026 |
|---|---|---|---|
| `JURY_SIZE()` | ValidatorRegistry | `0xafaec527` | **21** |
| `BFT_QUORUM()` | ValidatorRegistry | `0x16d46227` | **15** |
| `activeValidatorCount()` | ValidatorRegistry | `0x2340e8d3` | **0** |
| `totalSupply()` | CTXToken | `0x18160ddd` | **0** |

```bash
curl -s https://polygon-bor-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xeD9941279ce8949abEFE25C18b1E227d2012a63c","data":"0xafaec527"},"latest"]}'
```

**5. O espelho pós-quântico está vivo.** `latestEpochId()` tem seletor `0x73e2144f` e
devolve o número do dia UTC (`floor(unixtime / 86400)`) da última época ancorada. Ele
cresce **um por dia**, inclusive em dias sem evento, porque uma testemunha com buraco na
linha do tempo não é testemunha.

```bash
curl -s https://polygon-bor-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xD950cDdc624A9C16D6018B8DF95dfE9ED0729e38","data":"0x73e2144f"},"latest"]}'
```

## O que estes contratos não provam

Publicar endereço e código não prova que a rede está **em operação**. As leituras da tabela
acima dizem isso sozinhas: o token está em modo sombra (`totalSupply()` devolve 0) e não há
validador ativo (`activeValidatorCount()` devolve 0). O júri existe como **parâmetro** no
contrato, não como gente decidindo disputa. Contrato escrito não é rede rodando, e
preferimos escrever isso aqui a deixar alguém descobrir depois.
