Below is a **clean, registry-style `README.md`** suitable for a public **agent skills repository** consumable by **Vercel Skills CLI** and other tooling.

You can paste this directly as `README.md` at the repository root.

---

# xxidbr9-agents-skills-set

A curated collection of custom **agent skill definitions** designed for use with **Vercel Skills**, autonomous agents, and LLM-driven orchestration systems.

This repository follows a **convention-based layout** so skills can be fetched and installed automatically via tooling such as:

```
npx skills add <skill-name> --repo xxidbr9/xxidbr9-agents-skills-set
```

---

## Repository Purpose

This repository serves as:

* A **personal skill registry** for agent-based systems
* A **drop-in source** for Vercel Skills CLI
* A **reference implementation** for structuring reusable agent capabilities
* A **documentation-first skills library** (`skill.md` as the source of truth)

---

## Repository Structure

```
.
├── skills/
│   ├── rust-axum-framework/
│   │   └── skill.md
│   └── ...
└── README.md
```

### Rules

* One skill per folder
* Folder name equals skill name
* Each skill **must** contain `skill.md`
* `skill.md` must include YAML frontmatter

---

## Skill Format

Each skill is defined using structured Markdown.

Example:

```markdown
---
name: rust-axum-framework
description: Expertise and patterns for building production Axum services in Rust
version: 1.0.0
author: xxidbr9
---

## Capabilities

- Axum routing and middleware architecture
- WebSocket and Socket.IO integration
- Authentication and authorization layers
- Async Rust patterns for web backends
```

---

## Featured Skill: `rust-axum-framework`

### Description

The **`rust-axum-framework`** skill encapsulates practical, production-oriented knowledge for building **high-performance web services using Rust and Axum**.

It is designed for agents that need to:

* Reason about Axum application architecture
* Implement middleware, extractors, and layers
* Integrate WebSocket or Socket.IO (`socketioxide`)
* Design scalable async backends in Rust

### Related Repository

This skill is based on and aligned with the following framework repository:

**Rust Axum Framework**
[rust-axum-framework](./skills/rust-axum-framework)

That repository provides:

* Opinionated Axum project structure
* Middleware patterns
* Socket.IO and WebSocket examples
* Real-world Rust backend conventions

The skill acts as a **knowledge interface**, while the framework repository acts as the **implementation reference**.

---

## Usage with Vercel Skills

Install a skill directly from this repository:

```
npx skills add https://github.com/xxidbr9/xxidbr9-agents-skills-set --skill rust-axum-framework
```

The CLI resolves:

```
skills/rust-axum-framework/skill.md
```

via GitHub raw content.

---

## Compatibility

* Vercel Skills CLI
* Custom agent loaders
* Internal LLM orchestration pipelines
* Any tool capable of consuming Markdown-based skill definitions

---

## Versioning

* Each skill declares its own version
* Repository tags may be used for snapshot pinning
* Folder names are treated as stable identifiers

---

## License

Unless otherwise specified per skill, contents are provided for educational and development use.

---

If you want:

* a `CONTRIBUTING.md`
* a skill template generator
* automatic validation for `skill.md`
* a registry index (`skills.json`)

state it explicitly.
