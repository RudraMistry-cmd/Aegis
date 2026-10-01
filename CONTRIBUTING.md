# Contributing

## The specification is the contract

`spec/` is normative and is the input to implementation, not an afterthought. Before changing
behaviour, decide which document governs it:

- If the code disagrees with `spec/`, the code is wrong — fix the code.
- If the spec is wrong or ambiguous, change `spec/` in its own commit, with the reasoning, and only
  then change the code. Note it in `docs/CONFORMANCE.md` if it affects a claimed case.
- If you cannot tell what the spec requires, leave a `TODO` naming the exact section rather than
  guessing. Guessing is how a security library grows holes.

Every source file starts with a comment naming the spec section it implements. Keep that accurate.

## Rules that are not negotiable

- **Fail closed.** Uncertainty denies, throws or returns `null` — never allows. No code path may
  turn an exception, timeout or unavailable dependency into an allow.
- **No new error codes.** Use the catalog in `spec/errors.md` and `src/errors/index.ts`.
- **Dependency direction.** `src/domain` imports nothing. `src/rbac` and `src/policy` depend only on
  domain, errors and ports, and must never import `src/auth`. Nothing in `src/` imports a framework,
  driver or HTTP concept — those belong behind a port.
- **No ambient state.** Every operation takes an explicit `Subject` or `Principal`. There is no
  "current user", and time, randomness and ids come from injected ports so tests stay deterministic.
- **No secrets outside their own column.** Passwords, hashes and raw tokens must never reach a log,
  audit event, error, trace or `Principal`. Tests grep for them; keep those passing.

## Pull requests

1. `npm run lint` and `npm test` must pass. Both run in CI.
2. New or changed behaviour needs a test. If it matches a case in `spec/conformance.md`, add it to
   `test/conformance/` labelled with the case id and the GIVEN / WHEN / THEN, and list it in
   `docs/CONFORMANCE.md`. Otherwise add a unit test.
3. Any deviation from the spec, or any limitation of the in-memory adapter, belongs in the
   deviations section of `docs/CONFORMANCE.md` with a matching code comment.
4. Keep commits focused: a spec change, an implementation change and a refactor are three commits.
5. Update `CHANGELOG.md` under an `Unreleased` heading for anything user-visible.

## Style

TypeScript strict mode, ES2022, formatted by Prettier (`npm run format`) and linted by ESLint.
Prefer small pure functions and composition; avoid inheritance and large service classes. Public
types and functions carry explicit types and a short JSDoc comment. Comments explain *why* —
especially which spec rule forces an ordering — not *what*.
