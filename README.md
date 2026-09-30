# mcp-web — Tool MCP de obtención de contenido web

Prueba de concepto de una herramienta MCP que obtiene contenido de una URL
pública de forma segura, pensada para ser invocada por un agente de IA.

Trabajo de investigación — Pasantía ICONO LABS.
Sistema destino: arnés LeIA (`leia-core`).

## Qué resuelve

Una tool que sale a internet desde dentro de una red privada, cuyos
parámetros elige un modelo de lenguaje, hereda todos los riesgos clásicos
de red y agrega los propios de los agentes. Esta prueba de concepto
implementa y verifica las defensas correspondientes:

- **SSRF** (CWE-918): bloqueo de destinos internos, privados, link-local y
  del endpoint de metadata de nube, en IPv4 e IPv6.
- **DNS rebinding / TOCTOU** (CWE-367): el host se resuelve una sola vez y
  la conexión queda fijada a esa IP validada.
- **Redirecciones**: seguimiento manual, cada salto validado antes de
  conectar, con tope configurable.
- **Agotamiento de recursos** (CWE-400, CWE-409): límites aplicados durante
  la recepción, timeouts por petición y total.
- **Inyección indirecta**: eliminación de contenido invisible para una
  persona, marcado del contenido como no confiable, procedencia completa.
- **Política declarada**: sin política de salida, la tool no opera.

## Requisitos

- Python 3.13
- Sin conexión a internet (la suite corre completamente offline)

## Instalación

```bash
python -m venv venv
```

Activar el entorno virtual:

```bash
# Linux / macOS
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

Instalar dependencias:

```bash
pip install "mcp==1.12.4" httpx pytest
```

La versión de `mcp` está fijada por convención del sistema destino.

## Correr la suite

```bash
pytest -v
```

Deberían pasar los 54 tests. No hace falta levantar ningún servidor a mano
ni tener conexión a internet: cada test levanta los servidores de prueba
que necesita y los apaga al terminar.

Aparece un warning de `pydantic_settings` sobre un campo `lifespan`. Es
interno del SDK y no afecta los resultados.

## Estructura

| Archivo | Contenido |
|---|---|
| `server.py` | La tool, las defensas y el servidor MCP |
| `test_ataques.py` | Banco de ataques: cada riesgo de §5 y §7, con su defensa |
| `test_contrato_mcp.py` | Suite de contrato: invoca la tool por MCP, como el gateway |
| `host_prueba.py` | Host de prueba que juega el rol del gateway del arnés |

## Levantar el servidor a mano

```bash
python server.py
```

Levanta el servidor MCP en `http://127.0.0.1:8000/mcp`, transporte
`streamable-http`, modo stateless.

Para invocar la tool hay que mandar la cabecera `X-LeIA-Egress-Policy` con
la política de salida en JSON. Sin ella, la tool no opera.

## Cómo está armado el entorno de prueba

La suite no sale a internet en ningún momento. Dos mecanismos lo permiten:

- **Resolvedor DNS inyectable**: los tests pasan una función que responde
  lo que cada escenario necesita, incluso una IP distinta en cada consulta
  (que es como se simula el rebinding).
- **Fábrica de transporte controlada**: registra a qué IP decidió conectarse
  la tool y dirige el tráfico real a `127.0.0.1`, donde corren los
  servidores de prueba.

Esto permite simular direcciones públicas sin poseerlas ni contactarlas, y
verificar decisiones internas de la tool sin abrirla.

Ambas dependencias solo se pueden inyectar desde código Python. La tool MCP
expone un único parámetro, `url`, así que un modelo no tiene forma de
alterarlas.

## Documentación

- Informe de encuadre v1.1 — `docs/01_informe_scraping_seguro.pdf`
- Nota de convenciones v1.0 (ADR-020) — `docs/02_nota_convenciones_v1_0.pdf`
- Contrato de la herramienta — entregable (b)
- Anexo de lo no resuelto — entregable (e)
