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
| HourlyAnchor | `0x1B627fF9d6A341b27bD24207a3F6C8F9E8c1CDE9` | `0xA6D00dbbC96531282e60460f6f37bA2beC0Cb716` · **HourlyAnchor** | `exact_match` |
| MirrorAnchor | `0xD950cDdc624A9C16D6018B8DF95dfE9ED0729e38` | deploy direto, sem proxy | `exact_match` |
| TrustSealNFT | `0x751D70C3ac2b60A13603f1D61a480edcB82f563e` | `0x22633274DFf0f5D76134bcABb6d1A62F7456b438` · **TrustSealNFT** | `exact_match` |
| ValidatorRegistry | `0xeD9941279ce8949abEFE25C18b1E227d2012a63c` | `0x1Cda41848642eB207d4A98666a4D1066A222C0Ab` · **ValidatorRegistry** | `exact_match` |
| DisputeResolution | `0x7350B4E6fb59FeC74E736CB9eEFd13aF8800C1F4` | `0xAe0f20DBFD1C363798A8804b3f7A533114CCc710` · **DisputeResolution** | `match` |
| CTXToken | `0xB39a061E3776D8a0120Aaa3E20A1a1A93766afe1` | `0xa0881952B6ddEB7f938f1289239b981E5816C579` · **CTXToken** | `exact_match` |

Endereços de implementação relidos do slot ERC-1967 em 19 de agosto de 2026; estado de
verificação medido em 16 de agosto. O estado de verificação não regride sozinho, mas a
**implementação muda a cada upgrade** — por isso o comando abaixo lê o endereço da
implementação na hora, em vez de confiar nesta tabela.

> **Correção de 19/ago/2026.** Até esta data, quatro dos endereços de implementação desta
> tabela (HourlyAnchor, TrustSealNFT, ValidatorRegistry e CTXToken) estavam com o
> *checksum* EIP-55 errado. Os dígitos hexadecimais sempre foram os certos; o que estava
> errado era a caixa das letras. O defeito passou despercebido porque **chamada de RPC não
> valida checksum**: todos os `curl` desta página funcionavam. Quem valida é ferramenta que
> exige EIP-55, e foi o Sourcify recusando um deles com `Invalid address` que expôs o
> problema. Os oito endereços de proxy nunca tiveram esse defeito. Se você copiou algum
> endereço de implementação daqui antes de 19/ago, recopie.

### `exact_match` e `match` não são a mesma coisa

Seis contratos são `exact_match` e dois são `match`. Nos dois casos o **bytecode em
execução confere com o código-fonte publicado**, que é o que importa para auditar. A
diferença é o hash de metadados embutido no fim do bytecode: em `match` ele não é
idêntico, o que acontece quando o artefato foi compilado noutro ambiente. Dizemos os dois
nomes em vez de arredondar para o mais bonito.

### O cabeçalho do ContentRegistryV3 diz "V2", e isso é um rótulo envelhecido

Quem abrir o fonte verificado da implementação `0xCb7D14A2…` vai ler, no topo,
`@title ContentRegistryV2 — V7.5.0` num arquivo chamado `ContentRegistryV3.sol` cujo
contrato se chama `ContentRegistryV3` e cujo corpo já traz a V8.0.0, com `REGISTRAR_ROLE`
separado do `ANCHOR_ROLE`. Uma auditoria externa apontou a mistura em 19/ago/2026, e ela
está certa: o comentário não foi atualizado quando o contrato foi.

O que envelheceu é o rótulo, não o código. Nome do contrato, papéis e comportamento
sempre foram os da V8.0.0, e você confere isso **chamando o contrato**, não lendo o
comentário. A V7.5.0 tinha um papel só; a V8.0.0 separou dois:

```bash
# REGISTRAR_ROLE() — seletor 0xf68e9553 — só existe a partir da V8.0.0
curl -s https://polygon-bor-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x70a656FDcf9Cab966a5C9c283563a22f3D813c32","data":"0xf68e9553"},"latest"]}'

# ANCHOR_ROLE() — seletor 0xfd5f48c5 — vem desde antes
curl -s https://polygon-bor-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x70a656FDcf9Cab966a5C9c283563a22f3D813c32","data":"0xfd5f48c5"},"latest"]}'
```

Medido em 19/ago/2026, os dois respondem e são valores distintos:

| Papel | Valor |
|---|---|
| `REGISTRAR_ROLE` | `0xedcc084d3dcd65a1f7f23c65c46722faca6953d28e43150a467cf43e5c309238` |
| `ANCHOR_ROLE` | `0x08b5ce2e3163e37059f807346dad4dd6235ed44f92dced22992662cb45706362` |
| `PAUSER_ROLE` | `0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a` |

Vale rodar o controle negativo junto: chamar um seletor de função que não existe devolve
`execution reverted`. Sem isso, uma resposta vazia poderia ser confundida com sucesso.

Não dá para corrigir no que já está publicado. **Cabeçalho de contrato implantado não tem
"depois"**: o texto vai junto com o bytecode para sempre. Quem corrige é a próxima
implementação, cujo fonte já leva o cabeçalho certo. Consequência que preferimos dizer a
deixar alguém descobrir: como o *metadata hash* do Solidity cobre comentários, o arquivo
corrigido no repositório privado **não recompila byte a byte** para o que está em
`0xCb7D14A2…`. O runtime bytecode não mudou; o fonte de registro do que está no ar
continua sendo o verificado no Sourcify, e é ele que a tabela acima aponta.

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
