# Source layout

[Documentation](ReadMe.md) | [Project README](../ReadMe.md)

`Source/Main.rs` declares the Rust modules and command entry point. Source files
are grouped by responsibility. Tests stay beside the implementation they exercise.

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
