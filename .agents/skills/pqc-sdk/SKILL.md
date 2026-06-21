```markdown
# pqc-sdk Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill covers the development patterns and conventions found in the `pqc-sdk` Python repository. It provides guidance on file organization, code style, import/export practices, and testing patterns. This skill is designed to help contributors write consistent, maintainable code and understand the project's structure.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `key_generation.py`, `crypto_utils.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .crypto_utils import encrypt_message
    ```

### Export Style
- Use **named exports** (explicitly specify what is exported from modules).
  - Example:
    ```python
    __all__ = ['encrypt_message', 'decrypt_message']
    ```

### Commit Messages
- Commit messages are **freeform** and do not follow a strict prefix or template.
- Average commit message length is around 42 characters.

## Workflows

### Adding a New Module
**Trigger:** When you need to add new functionality to the SDK  
**Command:** `/add-module`

1. Create a new Python file using snake_case naming (e.g., `new_feature.py`).
2. Implement your functions or classes.
3. Use relative imports to access other modules in the package.
4. Add your public functions/classes to the `__all__` list for named exports.
5. Write corresponding tests in a file matching the pattern `new_feature.test.py`.

### Running Tests
**Trigger:** When you want to verify code correctness  
**Command:** `/run-tests`

1. Identify test files matching the `*.test.*` pattern (e.g., `crypto_utils.test.py`).
2. Run tests using your preferred Python test runner (e.g., `pytest`, `unittest`).
   - Example:
     ```bash
     pytest crypto_utils.test.py
     ```
3. Review test output and fix any failing tests.

## Testing Patterns

- Test files follow the pattern: `*.test.*` (e.g., `key_generation.test.py`).
- The specific testing framework is **unknown**; use standard Python testing tools unless otherwise specified.
- Place tests alongside or near the modules they test.

**Example test file:**
```python
# key_generation.test.py

from .key_generation import generate_keys

def test_generate_keys():
    public_key, private_key = generate_keys()
    assert public_key is not None
    assert private_key is not None
```

## Commands
| Command        | Purpose                                    |
|----------------|--------------------------------------------|
| /add-module    | Add a new module following project patterns |
| /run-tests     | Run all tests in the repository             |
```
