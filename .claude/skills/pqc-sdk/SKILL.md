```markdown
# pqc-sdk Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `pqc-sdk` TypeScript repository. You'll learn about file naming, import/export styles, commit message conventions, and how to write and run tests. This guide is designed to help contributors maintain consistency and quality across the codebase.

## Coding Conventions

### File Naming
- Use **PascalCase** for all file names.
  - Example: `CryptoUtils.ts`, `KeyManager.ts`

### Import Style
- Use **relative imports** for referencing modules.
  - Example:
    ```typescript
    import { encrypt } from './CryptoUtils';
    ```

### Export Style
- Use **named exports** exclusively.
  - Example:
    ```typescript
    // In CryptoUtils.ts
    export function encrypt(data: string): string { ... }
    export function decrypt(data: string): string { ... }
    ```

### Commit Messages
- Follow **conventional commit** format.
- Use prefixes like `feat` for features and `docs` for documentation.
  - Example:
    ```
    feat: add post-quantum key generation support
    docs: update README with usage examples
    ```

## Workflows

### Adding a New Feature
**Trigger:** When implementing new functionality  
**Command:** `/add-feature`

1. Create a new file using PascalCase (e.g., `NewFeature.ts`).
2. Use relative imports to include dependencies.
3. Export all new functions or classes as named exports.
4. Write or update corresponding test files (`*.test.ts`).
5. Commit changes with a `feat:` prefix and a concise description.

### Updating Documentation
**Trigger:** When improving or correcting documentation  
**Command:** `/update-docs`

1. Edit or add documentation files as needed.
2. Use clear, concise language.
3. Commit changes with a `docs:` prefix and a summary of the update.

### Writing and Running Tests
**Trigger:** When adding or updating tests  
**Command:** `/run-tests`

1. Create or update test files following the `*.test.ts` pattern.
2. Write tests for all new or changed functionality.
3. Use the project's test runner to execute tests (framework not specified; check project scripts).
4. Ensure all tests pass before committing.

## Testing Patterns

- Test files are named with the pattern `*.test.ts`.
- Place test files alongside the modules they test or in a dedicated test directory.
- Write tests for every exported function or class.
- Example test file:
  ```typescript
  // CryptoUtils.test.ts
  import { encrypt, decrypt } from './CryptoUtils';

  test('encrypt and decrypt should be inverses', () => {
    const data = 'secret';
    const encrypted = encrypt(data);
    expect(decrypt(encrypted)).toBe(data);
  });
  ```

## Commands
| Command         | Purpose                                 |
|-----------------|-----------------------------------------|
| /add-feature    | Add a new feature following conventions |
| /update-docs    | Update or improve documentation         |
| /run-tests      | Run all tests in the repository         |
```
