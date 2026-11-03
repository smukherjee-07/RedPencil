# Architecture overview

RedPencil is organized into API, core coordination, tool adapters, analysis,
schemas, storage, and reporting modules. The current repository is a scaffold;
these components are not implemented.

Planned request flow:

1. An API route receives an assessment request.
2. Core services validate scope and obtain required approval.
3. Authorized integrations or imported files provide assessment data.
4. Analysis modules normalize and correlate findings.
5. Reporting modules produce a report for review.

Active assessment integrations must remain explicitly scoped and require human
authorization. No active scanning or orchestration is implemented.
