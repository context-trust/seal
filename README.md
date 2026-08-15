# Espelho público de `@contexttrust/seal`

Este repositório é um **espelho somente-leitura** da implementação de referência do selo cøntextTrust e da sua especificação normativa. O desenvolvimento acontece em um monorepo privado; o que importa para quem verifica está aqui e no pacote publicado no npm.

Ele existe por um motivo específico: o protocolo afirma que **a verificação de um selo continua possível mesmo que a trustLayers deixe de existir**. Uma afirmação dessas exige que o código e a especificação estejam acessíveis fora da nossa infraestrutura, e não apenas dentro de um tarball.

## O que está aqui

| Caminho | O que é |
|---|---|
| `SPEC.md` | especificação **normativa** do selo V1.2: normalização canônica, BLAKE3, hash composto com binding de domínio, assinatura Ed25519, envelope, ordem de verificação, mapa de versões, e o que um selo **não** prova |
| `src/` | a implementação de referência em TypeScript, sem rede, sem banco e sem servidor |
| `test/` | vetores sintéticos e a suíte que qualquer pessoa roda para conferir conformidade |
| `LICENSE` · `NOTICE` | Apache-2.0 |

## Rodar a conformidade

```bash
npm install
npm run build
npm test
```

Saída esperada em 15/ago/2026: **24 testes, 24 passando**.

## O que NÃO está aqui, e por quê

- **Os vetores de selos reais de produção.** A suíte interna também roda contra selos verdadeiros, que carregam nome e conteúdo de pessoas. Publicá-los exporia conteúdo de terceiros para provar uma propriedade técnica, o que seria incoerente com um protocolo de proveniência e privacidade. Os vetores daqui são sintéticos e exercitam as mesmas fórmulas.
- **Contratos, aplicação e infraestrutura.** Os contratos on-chain são auditáveis de outro jeito, e melhor: estão **verificados no Sourcify e no Polygonscan**, com o código-fonte navegável a partir do endereço.

## Conferir sem confiar em nós

O pacote publicado é imutável por versão:

```bash
npm view @contexttrust/seal@1.4.0 dist.integrity
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
