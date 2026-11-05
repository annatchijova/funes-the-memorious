[English](README.md) · Español · [Technical README](docs/architecture/ARCHITECTURE.md)

# FUNES THE MEMORIOUS

> **Tu software paso las pruebas. ¿Podes probarlo?**
>
> Cada build tiene una historia. Cada prueba deja evidencia. Hace que ambas sean verificables.

**Funes the Memorious es una herramienta de procedencia para desarrollo QNX 8.0, alojada en Linux y escrita en C, que registra que se construyo y se probo realmente y permite que un revisor independiente verifique ese registro sin conexion.**

Repositorio: `annatchijova/funes-the-memorious`. Licencia: MIT (ver [LICENSE](LICENSE)).

El nombre viene del personaje de Borges que no olvida nada. Esta herramienta intenta lo contrario del recuerdo vago: recuerda exactamente que se recolecto, muestra de donde vino cada registro y dice con claridad donde termina la certeza. No es una memoria del exito. Es evidencia que puede ser desafiada.

> Esta es una adaptacion al español del [README principal en ingles](README.md). Ante cualquier diferencia, prevalece aquella.

---

## El problema

En sistemas embebidos y de tiempo real, "paso" suele ser una afirmacion, no evidencia. A quien no estuvo presente durante el build le entregan un binario, un fragmento de log y un resumen. Nada de eso responde las preguntas basicas: ¿que estado del codigo fuente produjo este binario?, ¿que toolchain y que target se eligieron?, ¿que comandos corrieron realmente y que salida produjeron?, ¿que pruebas corrieron, contra que artefacto, con que resultado?, ¿cambio algun artefacto, log o reporte desde que se registro?

Cuando esas preguntas no se pueden responder desde los artefactos, la confianza depende de confiar en quien produce. Para sistemas QNX — donde un binario equivocado o un cambio sin probar puede tener consecuencias de seguridad — esa dependencia es el problema que este proyecto aborda.

## Que es

Funes es un par de programas con un contrato deliberadamente acotado:

1. **Un colector en el host** (`funes`, planificado) corre en Linux. Ejecuta comandos de build y de prueba bajo observacion, registra codigos de salida y salida acotada, calcula hashes del codigo fuente y de los artefactos de salida, y sella el resultado en un paquete de evidencia versionado.
2. **Un verificador independiente** (`funes-verify`, planificado) corre sin conexion, en modo de solo lectura y sin depender de la logica interna del colector. Vuelve a comprobar la estructura y los hashes del paquete e informa exactamente que se sostiene y que no.

Entre ambos hay un formato publico de paquete que otro ingeniero puede verificar sin usar Funes. El formato — no el colector — es el contrato compartido.

## Estado actual

Los Niveles 0, 1, 3, 5 y 6 estan implementados y probados en el host Linux (`make`, `make test` con 122 verificaciones; ver [docs/STATUS.md](docs/STATUS.md)). El Nivel 4 esta completo en su parte host-only. El Nivel 2 (QNX) sigue `BLOCKED` porque no hay SDP instalado y no se afirma ningun resultado QNX. El estado vivo se mantiene en [docs/ROADMAP.md](docs/ROADMAP.md).

| Nivel | Nombre | Estado |
|---|---|---|
| 0 | Fundaciones e invariantes | DONE |
| 1 | Captura real en host y verificacion independiente | DONE (VERIFIED_HOST_ONLY) |
| 2 | Integracion genuina con QNX SDP 8.0 | BLOCKED — SDP no instalado en el host de desarrollo |
| 3 | Procedencia autenticada y politicas de confianza | DONE (VERIFIED_HOST_ONLY) |
| 4 | Evidencia de pruebas y runtime QNX | PARTIAL (host slice DONE, `VERIFIED_HOST_ONLY`; QEMU/QNX runtime `NOT_RUN`) |
| 5 | Comparacion forense y experiencia de auditoria | DONE (VERIFIED_HOST_ONLY) |
| 6 | Seguridad, rendimiento, portabilidad y release | DONE (`VERIFIED_HOST_ONLY`) |

## Limites honestos

- Un hash que coincide prueba consistencia contra una referencia, no que la referencia sea correcta.
- Una firma valida prueba control de una clave, no que una ejecucion haya ocurrido.
- Un paquete verificado no implica un entorno verificado ni un build reproducible.
- Ninguna evidencia QNX generada o falsa se etiqueta como ejecucion QNX real.
- La palabra es "tamper-evident" (evidencia de manipulacion), nunca "tamper-proof".

## Mas informacion

- Plan por niveles con criterios de entrada y salida: [docs/ROADMAP.md](docs/ROADMAP.md)
- Detalle tecnico: [Technical README](docs/architecture/ARCHITECTURE.md)
- Skills aplicadas: [docs/engineering/SKILLS-APPLIED.md](docs/engineering/SKILLS-APPLIED.md)
- Documentacion oficial de QNX: <https://www.qnx.com/developers/docs/8.0/index.html>
