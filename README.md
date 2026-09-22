# WebAudit 360

Ferramenta de auditoria automatizada e não destrutiva para sites autorizados.

## Arquivos

- `WEB_AUDIT_360_PROMPT.md` — prompt/projeto completo de auditoria.
- `webaudit360.py` — executor Python.
- `requirements.txt` — dependências.
- `.gitignore` — arquivos locais ignorados pelo Git.

## Instalação

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
playwright install chromium
```

## Uso básico

```bash
python webaudit360.py https://seusite.com --max-pages 50
```

Com teste visual/responsivo via navegador:

```bash
python webaudit360.py https://seusite.com --max-pages 50 --browser
```

Saída padrão em `webaudit360_output/`:

- `webaudit360_report.json`
- `webaudit360_report.md`
- screenshots, quando `--browser` estiver habilitado.

## O que o script automatiza

- crawling interno;
- status HTTP e tempo de resposta;
- SEO on-page básico;
- inventário de links, imagens e formulários;
- verificação de links quebrados;
- robots.txt e sitemap.xml;
- headers de segurança;
- flags básicas de cookies;
- TLS/certificado;
- acessibilidade estática básica;
- smoke tests responsivos e erros de console com Playwright;
- screenshots;
- relatórios JSON e Markdown.

## Limitações

UX/UI qualitativos, testes autenticados, regras de negócio, Core Web Vitals de campo, Lighthouse completo, pentest, SAST/DAST e geração do PDF executivo devem complementar a auditoria conforme o prompt do projeto.

## Segurança

Use somente em sites próprios ou ambientes para os quais você tenha autorização. O script não executa exploração ativa, brute force, SQL Injection, XSS ofensivo, alteração de dados ou outras ações destrutivas.
