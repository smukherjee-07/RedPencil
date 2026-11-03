# RedPencil

RedPencil is a scaffold for a security assessment and reporting application.

The current repository contains the planned project structure only. API routes,
analysis, integrations, persistence, approval flows, and report generation are
not implemented. Scanner adapter modules are placeholders and do not run tools.

## Project layout

- `app/api/`: planned API routes
- `app/core/`: planned application coordination and configuration
- `app/tools/`: planned import and scanner adapter interfaces
- `app/analysis/`: planned finding normalization and scoring
- `app/schemas/`: planned data models
- `app/storage/`: planned persistence
- `app/reporting/`: planned report generation
- `app/static/`: minimal static landing page
- `docs/`: design documentation
- `samples/`: inert example input files
- `tests/`: test module placeholders

## Development status

No application dependencies are defined yet. Review the design documents and
implement only authorized assessment workflows with explicit target scope and
human approval before any active testing.
