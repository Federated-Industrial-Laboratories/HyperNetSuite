# Source layout

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

`Source/Main.rs` declares the Rust modules and command entry point. Source files
are grouped by responsibility. Test code has a separate feature-grouped tree.

| Directory | Responsibility |
| --- | --- |
| Authority | Verified history, proofs, request streams, inspection and recovery |
| Authority/Deployments | Deployment records, client cache and activation |
| Authority/Domains | Domain commands, contexts and results |
| Authority/Epochs | Epoch transitions and evidence |
| Authority/Governance | Membership, applications, grants, tiers and policy |
| Authority/Recipients | Recipient identity continuity |
| Pages | Publication, catalogue, browsing and retained navigation |
| HyperPage | Inert markup, component, form and media schemas |
| Presentation | Layout, focus, scrolling, borders, forms and local motion |
| Graphical | Native Browser, Mail and Transfers windows, shared appearance and Page rendering |
| Terminal | Terminal session, input and graphics output |
| Media | Isolated import, canonical media and resumable retrieval |
| Forms, Mail, Transfers, Services | Explicit application workflows |
| Networks, Routing | Accepted profiles, private connections and diagnostics |
| Backup, Federation, Sealed | Archives, federation and confidential publication |
| Applications | Scoped application credentials and review adapters |
| Protocol, Runtime, Hosting | Shared wire, manifest and content policy contracts |
| Search, Storage | Scoped search and private local state |

Directory placement does not change Rust module names, wire formats or storage
paths. Explicit module paths in the declaring source file identify each child.
Presentation modules consume validated HyperPage data; network authority remains
in the client workflows.

## Test layout

`Tests/Unit/` contains Rust unit-test modules, grouped by the feature they test.
Explicit `#[cfg(test)]` module paths retain their original module names and private
access without placing test bodies in production source files. `Tests/Support/`
contains shared fixtures, builders and test-only accessors, included in their
owning module scope. Conditional fields and narrow instrumentation calls stay at
the implementation boundary they observe.

The existing executable probes and data vectors remain under `Tests/`. Cargo's
binary test targets compile the unit modules; `Tools/Check.sh` runs the maintained
checks. Rust unit tests and support files are excluded from release packages.
