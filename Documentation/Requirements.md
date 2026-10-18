# Requirements

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

These requirements describe intended behaviour. They are not implementation or
security certification claims.

- Provide independently usable Rust native graphical, terminal and command-line clients.
- Keep the clients independently installable and releasable from HyperNet.
- Use documented interfaces without direct access to server databases or secrets.
- Keep page viewing separate from mail, transfers and service authorisation.
- Render declarative pages without a browser engine or script execution.
- Treat page text, filenames, errors and media as untrusted input.
- Generate terminal control sequences only from trusted renderer operations.
- Support optional Kitty, iTerm2 and Sixel graphics with readable text fallbacks.
- Bound media decoding, output size, terminal queries and rendering work.
- Require explicit actions for downloads, external links and SSH sessions.
- Provide safe plain-text output for limited terminals and redirected commands.
- Keep credentials scoped to the selected network, identity and operation.
- Explain storage placement, offline delivery and privacy choices clearly.
- Default Private mailboxes to persistent storage only on user-selected systems.
- Keep Linux as the initial platform family while preserving portable interfaces.
