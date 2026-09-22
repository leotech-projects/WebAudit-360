# WebAudit 360 — Prompt Completo de Auditoria de Sites

## Objetivo

Executar uma auditoria completa, profissional, automatizada e documentada do site informado em `[COLAR URL DO SITE]`, analisando página por página: funcionalidades, UX, UI, responsividade, performance, SEO, acessibilidade, segurança cibernética, privacidade/LGPD, compatibilidade, conteúdo e qualidade técnica.

Ao final, gerar relatório analítico completo, matriz de problemas, backlog priorizado, plano de ação e PDF executivo em formato 16:9, estilo PowerPoint, com identidade visual inspirada no site auditado.

## Regras gerais

- Não inventar resultados.
- Não marcar como aprovado algo que não tenha sido testado.
- Informar `NÃO TESTADO — limitação técnica` quando aplicável.
- Diferenciar: `PROBLEMA CONFIRMADO`, `RISCO POTENCIAL`, `OPORTUNIDADE DE MELHORIA` e `ITEM APROVADO`.
- Não executar ações destrutivas, excluir dados, alterar configurações administrativas, derrubar serviços ou realizar pagamentos reais.
- Testes de segurança devem ser passivos ou não destrutivos e somente em ambiente autorizado.
- Para cada problema, registrar evidência, impacto, severidade, página afetada e recomendação.

## 1. Descoberta e mapeamento

Antes dos testes:

- Acessar a página inicial.
- Identificar páginas, menus, submenus, rotas, links internos/externos e funcionalidades.
- Analisar `sitemap.xml` e `robots.txt` quando disponíveis.
- Identificar formulários, login, cadastro, recuperação de senha, pesquisa, filtros, downloads, APIs, mapas, vídeos, widgets e integrações externas.
- Identificar páginas de erro, políticas de privacidade, termos de uso, cookies e áreas restritas.

Gerar tabela:

`Página | URL | Categoria | Funcionalidades | Autenticação necessária | Status`

## 2. Teste funcional página por página

Em cada página, testar:

- carregamento;
- menus e submenus;
- botões e CTAs;
- links, cards, banners e ícones clicáveis;
- campos e formulários;
- filtros, pesquisa e paginação;
- tabs, dropdowns, accordions e modais;
- login/logout, cadastro e recuperação de senha quando autorizados;
- upload/download quando seguro;
- compartilhamento e redes sociais;
- redirecionamentos;
- mensagens de sucesso/erro;
- retorno e atualização de página;
- URLs inválidas.

Tabela por teste:

`Página | Elemento | Ação | Resultado esperado | Resultado obtido | Status | Evidência | Recomendação`

Status: `APROVADO`, `FALHA`, `ALERTA`, `NÃO TESTÁVEL`.

## 3. UX

Avaliar:

- clareza e previsibilidade da navegação;
- facilidade de encontrar informações;
- hierarquia de informação;
- quantidade de cliques;
- consistência entre páginas;
- legibilidade;
- feedback após ações;
- prevenção e recuperação de erros;
- jornada do usuário;
- onboarding;
- conversão e CTAs;
- cadastro/login;
- formulários, busca e filtros;
- experiência mobile.

Identificar pontos de fricção, jornadas confusas, campos desnecessários e ações pouco intuitivas.

Atribuir notas de 0 a 10 para: UX geral, navegação, usabilidade, clareza, conversão e experiência mobile.

## 4. UI

Analisar:

- identidade visual, cores, tipografia e contraste;
- tamanho das fontes;
- botões, ícones, cards e imagens;
- espaçamentos, alinhamentos e grid;
- cabeçalho, rodapé, menus, modais e formulários;
- consistência visual;
- estados hover/focus/active/disabled;
- elementos sobrepostos, overflow e textos cortados.

## 5. Responsividade

Testar quando possível:

- 1920×1080
- 1366×768
- 1024×768
- 768×1024
- 430×932
- 390×844
- 360×800

Avaliar desktop, notebook, tablet e smartphone, incluindo orientação vertical e horizontal.

## 6. Performance

Executar ou simular métricas equivalentes a Lighthouse/PageSpeed e Core Web Vitals:

- Performance Score;
- FCP;
- LCP;
- INP;
- CLS;
- TTFB;
- Speed Index;
- Total Blocking Time.

Analisar imagens, JavaScript, CSS, fontes, lazy loading, cache, compressão, CDN, requisições HTTP e recursos bloqueantes.

Tabela:

`Métrica | Resultado | Referência recomendada | Status | Impacto | Solução`

## 7. SEO

Verificar:

- title e meta description;
- H1/H2/H3;
- canonical;
- robots.txt e sitemap.xml;
- indexabilidade;
- URLs amigáveis;
- links internos/externos;
- alt de imagens;
- conteúdo duplicado;
- páginas órfãs;
- redirects e 404;
- dados estruturados/Schema.org;
- Open Graph/Twitter Cards;
- favicon;
- SEO mobile.

Tabela:

`URL | Title | Description | H1 | Canonical | Indexável | Problemas | Recomendações`

## 8. Acessibilidade

Usar WCAG atual como referência. Testar:

- navegação por teclado;
- ordem de tabulação;
- foco visível;
- alt de imagens;
- contraste;
- labels;
- ARIA;
- leitores de tela quando possível;
- tamanho de áreas clicáveis;
- zoom;
- conteúdo não dependente apenas de cor.

Classificar: `CRÍTICO`, `ALTO`, `MÉDIO`, `BAIXO`.

## 9. Segurança cibernética

Somente testes não destrutivos. Verificar:

- HTTPS/TLS;
- redirecionamento HTTP→HTTPS;
- HSTS;
- Content-Security-Policy;
- X-Frame-Options;
- X-Content-Type-Options;
- Referrer-Policy;
- Permissions-Policy;
- cookies Secure/HttpOnly/SameSite;
- CORS;
- exposição de versões e informações técnicas;
- diretórios/arquivos sensíveis publicamente expostos;
- endpoints de API;
- mensagens de erro;
- gerenciamento de sessão;
- recuperação de senha;
- enumeração de usuário;
- proteção contra brute force;
- indícios de XSS, SQL Injection, CSRF, clickjacking e open redirect, sem exploração destrutiva;
- secrets/tokens expostos no frontend.

Usar OWASP Top 10 como referência.

Tabela:

`Risco | URL | Evidência | Severidade | Impacto | Recomendação`

## 10. Privacidade e LGPD

Verificar:

- Política de Privacidade;
- Termos de Uso;
- Política/banner de cookies;
- consentimento e recusa;
- finalidade da coleta;
- dados solicitados em formulários;
- coleta excessiva;
- compartilhamento;
- contatos do controlador;
- meios de exclusão/correção de dados.

Não emitir parecer jurídico definitivo.

## 11. Compatibilidade

Sempre que possível avaliar Chrome, Edge, Firefox e Safari, observando layout, JavaScript, formulários, vídeos, imagens, menus e fontes.

## 12. Links

Verificar todos os links internos e externos e identificar 404, 403, 5xx, redirects inesperados, HTTP sem HTTPS e páginas removidas.

Tabela:

`Página origem | Texto do link | URL destino | HTTP status | Resultado | Recomendação`

## 13. Formulários

Verificar campos obrigatórios/opcionais, validação, formatos inválidos, limites de caracteres, mensagens, sanitização aparente, CAPTCHA, spam, duplo envio, responsividade e acessibilidade. Não enviar spam nem dados sensíveis.

## 14. Console e rede

Verificar erros JavaScript, warnings, requisições falhas, 4xx/5xx, CORS, APIs indisponíveis, imagens/fontes/scripts inexistentes.

Tabela:

`Página | Erro | Recurso | Código | Impacto | Solução`

## 15. Conteúdo

Avaliar ortografia, textos duplicados/incompletos/desatualizados, clareza, consistência, nomes/datas divergentes, CTAs e microcopy.

## 16. Testes adicionais recomendados

Avaliar necessidade de:

- testes unitários;
- E2E;
- integração;
- regressão;
- carga;
- stress;
- escalabilidade;
- pentest autorizado;
- SAST/DAST;
- análise de dependências;
- API testing;
- banco de dados;
- backup e disaster recovery;
- uptime monitoring;
- observabilidade;
- Analytics;
- testes A/B e conversão.

## 17. Relatório analítico

Estrutura mínima:

1. Capa
2. Resumo executivo
3. Data e hora
4. URL
5. Objetivos
6. Escopo
7. Metodologia
8. Ferramentas utilizadas
9. Mapa do site
10. Inventário de páginas
11. Testes executados
12. Funcionalidade
13. UX
14. UI
15. Responsividade
16. Performance
17. SEO
18. Acessibilidade
19. Segurança
20. Privacidade/LGPD
21. Compatibilidade
22. Links
23. Formulários
24. Console/rede
25. Conteúdo
26. Problemas identificados
27. Recomendações
28. Matriz de riscos
29. Plano de correção
30. Backlog técnico
31. Conclusão

## 18. Matriz de problemas

`ID | Problema | Página | Categoria | Severidade | Impacto | Complexidade | Recomendação | Prioridade`

Severidade: `CRÍTICA`, `ALTA`, `MÉDIA`, `BAIXA`, `INFORMATIVA`.

## 19. Priorização

- PRIORIDADE 1 — IMEDIATA: segurança, indisponibilidade, perda de dados, funcionalidades essenciais quebradas.
- PRIORIDADE 2 — ALTA: UX grave, performance, SEO, acessibilidade e erros funcionais relevantes.
- PRIORIDADE 3 — MÉDIA: melhorias de UI, usabilidade e otimização.
- PRIORIDADE 4 — EVOLUTIVA: novas funcionalidades e melhorias arquiteturais.

## 20. Score final

Atribuir notas de 0 a 100 para:

- Funcionalidade
- UX
- UI
- Responsividade
- Performance
- SEO
- Acessibilidade
- Segurança
- Privacidade/LGPD
- Compatibilidade
- Qualidade técnica

Calcular `SCORE GERAL DO SITE: XX/100` e justificar tecnicamente.

## 21. Backlog

Gerar:

`ID | Tarefa | Problema relacionado | Categoria | Prioridade | Benefício | Complexidade | Dependência`

Organizar em: `IMEDIATO`, `CURTO PRAZO`, `MÉDIO PRAZO`, `EVOLUTIVO`.

## 22. Evidências visuais

Quando possível:

- capturar screenshots;
- marcar visualmente problemas;
- inserir legenda e página;
- priorizar problemas críticos/altos;
- evitar evidências redundantes.

## 23. Identidade visual do relatório

Antes de gerar o PDF, analisar o site e extrair/inferir:

- cores principais/secundárias;
- cor de destaque e fundo;
- estilo visual;
- tipografia aproximada;
- formato de cards e botões;
- ícones;
- logotipo e favicon;
- elementos gráficos relevantes.

O relatório deve ser inspirado visualmente no site sem prejudicar legibilidade.

## 24. PDF final estilo PowerPoint

Gerar obrigatoriamente:

`AUDITORIA_[NOME_DO_SITE]_[DATA].pdf`

Formato preferencial 16:9 horizontal; cada página deve funcionar como um slide.

### Estrutura sugerida

- Slide 1: capa
- Slide 2: resumo executivo
- Slide 3: score geral
- Slide 4: mapa do site
- Slide 5: metodologia
- Seções: Funcionalidade, UX, UI, Responsividade, Performance, SEO, Acessibilidade, Segurança, LGPD, Compatibilidade, Links, Formulários, Console/Rede e Conteúdo
- Slides específicos para problemas críticos/altos
- Gráficos de severidade, categoria, score, prioridades e aprovação/falha
- Slide de Top Problemas
- Roadmap em fases
- Backlog executivo: Agora / Próximo / Depois
- Conclusão
- Slide final de auditoria concluída

### Qualidade do PDF

- identidade visual coerente;
- boa resolução;
- textos legíveis;
- tabelas e gráficos sem cortes;
- screenshots proporcionais;
- boa hierarquia visual;
- pouco texto por slide;
- margens e contraste adequados.

### Controle de qualidade

Antes da entrega:

1. abrir o PDF;
2. revisar todas as páginas;
3. verificar cortes e sobreposições;
4. validar gráficos e tabelas;
5. validar screenshots;
6. conferir URLs, nomes e notas;
7. corrigir erros antes da entrega.

## 25. Entrega final

Entregar:

1. resumo executivo;
2. relatório analítico completo;
3. matriz de problemas;
4. plano de ação;
5. backlog;
6. lista de testes executados;
7. resultados;
8. PDF profissional;
9. link para o PDF;
10. quantidade de páginas analisadas;
11. quantidade de testes executados;
12. quantidade de problemas por severidade.

## Início

**SITE:** `[COLAR URL DO SITE]`

Execute primeiro o mapeamento, depois os testes página por página, consolide os resultados e, por fim, gere o relatório e o PDF profissional.
