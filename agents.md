# Agents Instructions — Application Development with VS Code & GitHub Copilot

## Purpose

This file provides standing instructions for AI agents (GitHub Copilot, Copilot Edits, Copilot Chat, and related tools) operating in this repository. All agents must read and follow these instructions before taking any action.

---

## 1. Project Overview

> **Fill in before use:**
> - **Project name:**
> - **Tech stack:** (e.g., TypeScript / React / Node.js / PostgreSQL)
> - **Package manager:** (e.g., npm / pnpm / yarn)
> - **Test framework:** (e.g., Jest / Vitest / Playwright)
> - **Primary language version:** (e.g., Node 20, Python 3.12)

---

## 2. Code Style & Conventions

### General
- Follow the conventions already present in existing files — consistency beats personal preference.
- Keep functions small and single-purpose. Prefer flat logic over deeply nested structures.
- Use descriptive variable names; avoid single-letter names except in short loops or math contexts.
- Prefer explicit over implicit: no magic numbers, no unexplained defaults.

### Language-Specific Defaults
- **TypeScript/JavaScript:** Strict mode on. Prefer `const` over `let`; avoid `var`. Use `async/await` over `.then()` chains.
- **Python:** Follow PEP 8. Use type hints. Prefer dataclasses or Pydantic for structured data.
- **CSS/SCSS:** Use utility classes or a consistent naming convention (BEM, CSS Modules, Tailwind, etc. — match what's in the project).

### File & Folder Structure
- New files go in the most specific appropriate directory — don't dump things in root or `src/`.
- One primary export per file unless there is a clear grouping reason.
- Name files after what they contain: `UserCard.tsx`, `auth.service.ts`, `parse_csv.py`.

---

## 3. Agent Behavior Rules

### Always Do
- Read existing code in the affected area before making changes — understand the pattern first.
- Preserve existing formatting, spacing, and comment style in modified files.
- Write or update tests when adding or changing logic.
- Add inline comments for anything non-obvious, especially business rules or workarounds.
- Keep changes focused — only modify what the task requires.

### Never Do
- Do not delete code without being explicitly asked to.
- Do not rename files, functions, or variables unless renaming is the task.
- Do not change unrelated files to "clean things up" during a task.
- Do not introduce new dependencies without flagging them for human review.
- Do not commit secrets, credentials, API keys, or `.env` values.
- Do not bypass TypeScript errors with `// @ts-ignore` or `any` — fix the root cause.

### When Uncertain
- If requirements are ambiguous, stop and ask a clarifying question before proceeding.
- If a task could be done in two significantly different ways, outline both options briefly and ask which to proceed with.
- If an existing pattern is unclear or inconsistent, flag it rather than silently picking one approach.

---

## 4. GitHub Copilot — Inline & Chat Usage

### Inline Completions
- Accept completions only when they match the intent of what you're writing — review before Tab.
- Treat completions as suggestions, not ground truth. Always verify logic, especially for edge cases.
- If Copilot completes with a library or API you don't recognize, verify it exists and is current before using it.

### Copilot Chat (`Ctrl+Shift+I` / `#` references)
- Use `#file` to give Copilot context about the specific file you're working in.
- Use `#selection` to ask about a highlighted block.
- Use `@workspace` for questions about the overall project structure.
- Use `@terminal` to explain errors or suggest commands.
- Keep questions specific — vague prompts produce vague answers.

### Copilot Edits (Multi-file)
- Before accepting an edit session, review the list of files it intends to touch.
- Reject any changes to files outside the stated scope.
- Use the diff view to check every change before accepting.

---

## 5. Testing Requirements

- All new functions with logic must have at least one unit test.
- Tests should cover the happy path, at least one edge case, and expected error states.
- Test file naming: `*.test.ts` / `*.spec.ts` co-located with source, or inside `__tests__/` — match project convention.
- Do not mock everything — integration-level tests for data flows are encouraged.
- Tests must pass before marking a task complete. Run: `[insert test command, e.g., npm test]`

---

## 6. Git & Version Control

- **Branch naming:** `feature/short-description`, `fix/short-description`, `chore/short-description`
- **Commit messages:** Use Conventional Commits format:
  - `feat: add user authentication`
  - `fix: correct null check in parser`
  - `chore: update dependencies`
  - `docs: add API usage examples`
- Each commit should represent one logical change.
- Do not commit generated files, `node_modules`, build artifacts, or `.env` files.
- The `main` / `master` branch is protected — always work on a feature branch.

---

## 7. Security Practices

- Never hard-code credentials, tokens, or secrets — use environment variables.
- Validate and sanitize all user input before use.
- Do not log sensitive data (passwords, tokens, PII).
- Use parameterized queries for all database operations — no string concatenation for SQL.
- Flag any third-party library additions for security review if they handle auth, crypto, or data storage.

---

## 8. Performance Guidelines

- Avoid blocking the main thread — use async operations for I/O.
- Do not fetch data inside render loops or tight iteration cycles.
- Prefer lazy loading for large modules or heavy assets.
- Profile before optimizing — do not pre-optimize unproven bottlenecks.
- Cache results only when there is a measurable reason to.

---

## 9. Documentation

- Public functions and exported modules must have JSDoc / docstring comments.
- Update the relevant README section if you change setup steps, environment variables, or public APIs.
- Leave `TODO:` comments for intentional deferrals, including a brief note explaining why.
- Remove stale comments that no longer reflect the code.

---

## 10. Task Completion Checklist

Before marking any task done, verify:

- [ ] Code follows the conventions in this file and in the surrounding codebase
- [ ] Tests are written and passing
- [ ] No secrets or credentials are present in changed files
- [ ] No unrelated files were modified
- [ ] Commit message follows Conventional Commits format
- [ ] Inline comments added where logic is non-obvious
- [ ] Documentation updated if public APIs or setup changed

---

## 11. Out-of-Scope Actions

Agents must **not** do any of the following without explicit human instruction:

- Deploy to any environment (staging, production, preview)
- Modify CI/CD pipeline configuration
- Change access controls, permissions, or authentication settings
- Create, modify, or delete database schemas in a live environment
- Publish packages or releases
- Merge pull requests

---

## Revision History

| Date | Change | Author |
|------|--------|--------|
| YYYY-MM-DD | Initial version | |