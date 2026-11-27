# 🛡️ Guardian

> **Revisor de PRs open source en Rust, *zero-infra* y BYOK** — enfocado estrictamente en bugs lógicos y *edge cases* en tiempo de ejecución respaldados por un escenario de fallo concreto.

[Read in English (README.md)](README.md) · [Privacidad y Datos](PRIVACY.md) · [Modelo de Seguridad](SECURITY.md) · [Contribuir](CONTRIBUTING.md)

<p align="center">
  <img src="assets/guardian-processing.svg" alt="Caballero de Guardian partiendo bugs entrantes" width="336" height="120" />
</p>

## ¿Por qué Guardian?

La mayoría de revisores con IA inundan los Pull Requests con reglas de estilo, líneas inventadas y comentarios repetidos en cada commit. Guardian está construido alrededor de un **embudo determinista de 7 etapas** en Rust:

1. **Anclaje al diff:** descarta rutas o líneas alucinadas por el LLM.
2. **Solo código del PR:** ignora quejas sobre código legado intacto.
3. **Filtro de categoría y severidad:** solo `bug` y `edge_case`.
4. **Escenario concreto obligatorio:** sin explicaciones vagas ("podría fallar").
5. **Agrupación intra-PR:** colapsa patrones repetidos en un solo comentario.
6. **Deduplicación `SHA-256` + GraphQL `isResolved`:** nunca vuelve a abrir hilos ya resueltos ni repite hallazgos aunque cambien los números de línea.
7. **`guardian-ignore` y tope máximo de comentarios** por PR.

Además extrae **contexto AST intra-archivo con Tree-sitter** (Rust, TypeScript/TSX/JS, Python y PHP) para respetar validaciones previas dentro de la misma función sin hacer `actions/checkout`.

## Inicio rápido en 5 minutos

### 1. Agrega `.guardian.yml` en tu rama principal (`main`)

```yaml
version: 1
language: es
review:
  min_severity: medium
  max_comments: 6
  ignore_paths:
    - "docs/**"
    - "migrations/**"
limits:
  max_files: 30
rules:
  - id: guard-zero-div
    text: "Valida siempre denominadores distintos de cero en cálculos de facturación."
behavior:
  suggestions: true
  fail_on_error: false
```

Puedes validarlo localmente en cualquier momento con `guardian validate .guardian.yml`.

### 2. Agrega `.github/workflows/guardian.yml`

```yaml
name: Guardian Review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write
  checks: write

concurrency:
  group: guardian-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: meden2010/guardian@v1.0.0
        with:
          model: gpt-4o-mini
          api_key: ${{ secrets.GUARDIAN_LLM_API_KEY }}
```

> **¿Modelo local con Ollama / vLLM en runner autoalojado?**
> Pasa `base_url: http://<host>:11434/v1`, `model: qwen2.5-coder:7b` y `allow_insecure_http: "true"` — tu código nunca sale de tu red privada.

## Qué NO hace Guardian

- **No revisa estilo, formato ni lint** (usa `clippy`, `eslint`, `ruff` o `phpstan`).
- **No tiene servidor SaaS ni telemetría** (ver [PRIVACY.md](PRIVACY.md)).
- **No hace commits automáticos** — publica revisiones `COMMENT` y bloques nativos ```` ```suggestion ```` de 1 clic para que un humano apruebe.
- **No ejecuta código del PR** — lee `.guardian.yml` exclusivamente desde `base_sha` y archivos pasivamente vía API de GitHub.

## Licencia

Licencia dual `MIT OR Apache-2.0` ([LICENSE-MIT](LICENSE-MIT)).
