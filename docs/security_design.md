# Security design

This document records design constraints for future implementation. The
current scaffold does not authenticate users, execute tools, or process
assessment requests.

- Require explicit ownership or authorization for every assessment target.
- Validate and persist target scope before any active test.
- Require human approval for active or state-changing actions.
- Keep imported evidence separate from executable commands.
- Avoid logging credentials, tokens, or sensitive report contents.
- Record security-relevant decisions and actions in an auditable manner.
- Apply least privilege to application and container execution.
