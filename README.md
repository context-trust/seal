# Espelho público de `@contexttrust/seal`

Este repositório é um **espelho somente-leitura** da implementação de referência do selo cøntextTrust e da sua especificação normativa. O desenvolvimento acontece em um monorepo privado; o que importa para quem verifica está aqui e no pacote publicado no npm.

Ele existe por um motivo específico: o protocolo afirma que **a verificação de um selo continua possível mesmo que a trustLayers deixe de existir**. Uma afirmação dessas exige que o código e a especificação estejam acessíveis fora da nossa infraestrutura, e não apenas dentro de um tarball.

## O que está aqui

| Caminho | O que é |
|---|---|
| `SPEC.md` | especificação **normativa** do selo V1.2: normalização canônica, BLAKE3, hash composto com binding de domínio, assinatura Ed25519, envelope, ordem de verificação, mapa de versões, e o que um selo **não** prova |
| `src/` | a implementação de referência em TypeScript, sem rede, sem banco e sem servidor |
| `test/` | vetores de conformidade (selos **reais**, ver abaixo) e a suíte que qualquer pessoa roda |
| `LICENSE` · `NOTICE` | Apache-2.0 |

## Rodar a conformidade

```bash
npm install
npm run build
npm test
```

Saída esperada em 15/ago/2026: **24 testes, 24 passando**.

## De onde vêm os vetores de teste

Os cinco vetores em `test/vectors.json` são **selos reais**, extraídos da tabela de produção. Nenhum foi construído para o teste, e é justamente por isso que valem: eles exercitam as fórmulas contra dados que o produto gerou de verdade, com linhagem de 2, 8 e 9 ancestrais, texto com acento, emoji e quebra de linha, e casos com e sem mídia.

Três esclarecimentos que um auditor vai querer, e que preferimos dar antes da pergunta:

- **Todos os cinco pertencem a uma única pessoa, o autor deste repositório, e estão marcados como registros de teste** (`is_test`). Nenhum conteúdo de terceiro aparece aqui.
- **No produto, a visibilidade deles é privada ou protegida.** Isso significa que `api/verify` não devolve o texto, e este repositório devolve. Não é vazamento nem inconsistência do protocolo: é uma decisão de quem é dono dos cinco selos, tomada para que a conformidade possa ser conferida contra dado real. Se a visibilidade fosse a de outra pessoa, a decisão não seria nossa para tomar.
- **Nenhuma chave privada aparece.** Cada vetor traz apenas a chave pública, os hashes e a assinatura. A verificação de assinatura é feita com a pública, que é pública por definição.

Uma versão anterior deste README dizia que os vetores eram sintéticos. Estava errado, e a contradição foi apontada por uma auditoria externa em 19/ago/2026. O texto acima é o que os arquivos sempre disseram.

## O que NÃO está aqui, e por quê

- **Contratos, aplicação e infraestrutura.** Os contratos on-chain são auditáveis de outro jeito, e melhor: as implementações estão **verificadas no Sourcify** (seis `exact_match` e dois `match` nos oito contratos publicados), com o código-fonte navegável a partir do endereço. A publicação de todas elas também no Polygonscan está sendo completada; onde os dois divergirem, o Sourcify é a referência.

## Conferir sem confiar em nós

O pacote publicado é imutável por versão:

```bash
npm view @contexttrust/seal@1.4.1 dist.integrity
```

Um selo real, verificável por qualquer um, sem cadastro:

```
https://trustlayers.com.br/api/verify/e2f47c2f3656ff3a
```

E o registro on-chain, em Polygon mainnet:

```bash
curl -s https://polygon-bor-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x70a656FDcf9Cab966a5C9c283563a22f3D813c32","data":"0x54fd4d50"},"latest"]}'
```

*cøntextTrust · Apache-2.0 · proof, not promises.*
