# C Interfaces and Implementations Style Guide

This document contains the C Interfaces and Implementations (Hanson, 1996) patterns and GNU C style guidelines used throughout the socket library codebase.

## Overview

This codebase follows **C Interfaces and Implementations** (Hanson, 1996) patterns strictly, combined with GNU C coding style. All code must maintain this style for consistency.

## Header File Style (*.h)

### Include Guard Pattern:
```c
#ifndef MODULENAME_INCLUDED
#define MODULENAME_INCLUDED

/* ... header contents ... */

#endif
```

**Rules**:
- Include guards MUST use `FILENAME_INCLUDED` suffix pattern
- Examples: `ARENA_INCLUDED`, `EXCEPT_INCLUDED`, `SOCKET_INCLUDED`

### Module Documentation:
```c
/**
 * ModuleName - Brief module description
 *
 * Detailed description of module purpose, features, and behavior.
 * Include information about thread safety, performance characteristics,
 * and any important usage notes.
 *
 * Features:
 * - Feature 1 with brief description
 * - Feature 2 with brief description
 *
 * Usage example:
 *   ModuleName_T instance = ModuleName_new();
 *   ModuleName_operation(instance);
 *   ModuleName_free(&instance);
 */
```

### Include Order:
```c
/* System headers first (alphabetical or logical order) */
#include <stddef.h>
#include <stdint.h>

/* Then project headers */
#include "core/Arena.h"
#include "core/Except.h"
```

### Type Definition Pattern:
```c
#define T ModuleName_T
typedef struct T *T;  /* Opaque pointer type */
```

**Rules**:
- Type definition uses `T` macro pattern
- Only opaque pointer types exposed in headers
- Structure definition goes in implementation file

### Function Declarations:
```c
/**
 * ModuleName_new - Create a new module instance
 *
 * Returns: New instance, or NULL on failure
 * Thread-safe: Yes
 */
extern T ModuleName_new(void);

/**
 * ModuleName_free - Free module instance
 * @instance: Pointer to instance pointer (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void ModuleName_free(T *instance);
```

**Rules**:
- Function declarations MUST use `extern` keyword
- Doxygen-style function documentation required
- Use `@param`, `@returns`, etc. for documentation
- Include thread safety notes where applicable

### Constants and Macros:
```c
/* Define constants after type definitions */
#define MODULE_DEFAULT_SIZE 1024
#define MODULE_MAX_COUNT    100

/* Macros for module-specific operations */
#define MODULE_OPERATION(x) do { /* ... */ } while(0)
```

### Header Cleanup:
```c
#undef T
#endif
```

**Rules**:
- `#undef T` at end of header file before `#endif`
- Clean up macro namespace

### Complete Header Example:
```c
#ifndef MODULENAME_INCLUDED
#define MODULENAME_INCLUDED

#include <stddef.h>  /* System headers first */

/**
 * ModuleName - Brief module description
 *
 * Detailed description of module purpose, features, and behavior.
 * Include information about thread safety, performance characteristics,
 * and any important usage notes.
 *
 * Features:
 * - Feature 1 with brief description
 * - Feature 2 with brief description
 *
 * Usage example:
 *   ModuleName_T instance = ModuleName_new();
 *   ModuleName_operation(instance);
 *   ModuleName_free(&instance);
 */

#define T ModuleName_T
typedef struct T *T;  /* Opaque pointer type */

/**
 * ModuleName_new - Create a new module instance
 *
 * Returns: New instance, or NULL on failure
 * Thread-safe: Yes
 */
extern T ModuleName_new(void);

/**
 * ModuleName_free - Free module instance
 * @instance: Pointer to instance pointer (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void ModuleName_free(T *instance);

#undef T
#endif
```

## Implementation File Style (*.c)

### Module Documentation:
```c
/**
 * ModuleName.c - Module implementation description
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */
```

### Include Order:
```c
/* System headers first (alphabetical or logical order) */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Then project headers */
#include "core/ModuleName.h"
#include "core/SocketConfig.h"
```

### Type Definition:
```c
#define T ModuleName_T

/* Structure definition (NOT exposed in header) */
struct T {
    /* Structure members */
    Arena_T arena;
    int field1;
    size_t field2;
};
```

### Function Organization:
```c
/* Static helper functions BEFORE public functions */
static void
helper_function(T instance)
{
    /* Implementation */
}

/* Public function implementations */
T
ModuleName_new(void)
{
    /* Implementation */
}
```

**Rules**:
- Static helpers before public functions
- Return type on separate line (GNU C style requirement)

### Function Documentation:
```c
/**
 * function_name - Brief description of function purpose
 * @param1: Description of first parameter
 * @param2: Description of second parameter
 *
 * Returns: Description of return value (or void)
 * Raises: Description of exceptions that may be raised
 * Thread-safe: Yes/No with explanation if applicable
 *
 * Additional implementation details, usage notes, or constraints.
 */
```

### Function Definition Style (GNU C):
```c
/* Return type on separate line */
T
ModuleName_new(void)
{
    T instance;

    instance = malloc(sizeof(*instance));
    if (instance == NULL)
        return NULL;

    /* Initialize */
    return instance;
}

void
ModuleName_free(T *instancep)
{
    assert(instancep && *instancep);

    free(*instancep);
    *instancep = NULL;
}
```

**Rules**:
- Return type on separate line from function name
- Opening brace on same line as function name
- Function parameters documented with `@param`
- Return values documented with `Returns:`
- Exceptions documented with `Raises:`

### Implementation Cleanup:
```c
#undef T
```

**Rules**:
- `#undef T` at end of implementation file
- No trailing whitespace

### Complete Implementation Example:
```c
/**
 * ModuleName.c - Module implementation description
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>  /* System headers first */
#include <stdlib.h>
#include "core/ModuleName.h"  /* Project headers */
#include "core/SocketConfig.h"

#define T ModuleName_T

struct T {
    /* Structure members */
    int field;
};

/* Static helper functions first */
static void
helper_function(T instance)
{
    /* Implementation */
}

/* Public function implementations */
T
ModuleName_new(void)
{
    T instance;

    instance = malloc(sizeof(*instance));
    if (instance == NULL)
        return NULL;

    /* Initialize */
    return instance;
}

void
ModuleName_free(T *instancep)
{
    assert(instancep && *instancep);

    free(*instancep);
    *instancep = NULL;
}

#undef T
```

## GNU C Style Guidelines

### Indentation:
- 8-space indentation (tabs or spaces, but consistent)
- No tabs in middle of line (only at beginning)

### Line Length:
- Prefer to keep lines under 80 columns
- Can exceed for readability (no hard limit enforced)

### Braces:
```c
/* Opening brace on same line for functions, control structures */
if (condition) {
    /* code */
}

while (condition) {
    /* code */
}

for (int i = 0; i < n; i++) {
    /* code */
}

/* Function opening brace on same line as function name */
void
function_name(int param)
{
    /* code */
}
```

### Spacing:
```c
/* Space after if, while, for, switch */
if (x)
while (y)
for (i = 0; i < n; i++)
switch (z)

/* Space around operators */
x = y + z;
if (a == b)
c += d;

/* No space before semicolon */
statement;

/* Space after comma */
function(a, b, c);
```

### Pointer Alignment:
```c
/* Use "type *ptr" not "type* ptr" */
int *ptr;
char *str;
ModuleName_T *instance;
```

### Function Calls:
```c
/* No space before opening parenthesis */
function(arg1, arg2);

/* Space after comma */
function(a, b, c);
```

### Conditionals:
```c
/* Single statement can omit braces, but prefer braces for clarity */
if (condition)
    statement;

/* Multiple statements require braces */
if (condition) {
    statement1;
    statement2;
}

/* Prefer early returns over nested conditionals */
if (error_condition)
    return ERROR;

/* ... rest of function ... */
```

## Naming Conventions

### Types:
- `ModuleName_T` for opaque types
- Examples: `Socket_T`, `Arena_T`, `SocketPoll_T`

### Public Functions:
- `Module_Verb` pattern
- Examples: `Socket_bind`, `Arena_alloc`, `SocketPoll_wait`
- First letter capitalized for module name

### Private Functions:
- `lower_snake_case`
- Examples: `socket_hash`, `parse_address`, `validate_input`
- Static functions only

### Constants:
- `MODULE_NAME` or `SOCKET_MODULE_NAME`
- Examples: `SOCKET_MAX_SIZE`, `ARENA_MAX_ALLOC_SIZE`
- All uppercase with underscores

### Exceptions:
- `Module_ErrorType` pattern
- Examples: `Socket_Failed`, `Arena_Failed`, `SocketPoll_Failed`

## Comment Style

### Documentation Comments:
```c
/* Use /** */ for documentation comments (functions, modules) */
/**
 * Function documentation
 */

/* Use /* */ for code comments */
/* This is a code comment explaining why, not what */

/* Use // sparingly, only for very short inline comments */
int x;  // Counter
```

### Comment Guidelines:
- Comments should explain WHY, not WHAT (code should be self-documenting)
- Use Doxygen-style documentation for all public APIs
- Include thread safety notes where applicable
- Document unusual behavior or edge cases

## Opaque Type Pattern

### Header (Public Interface):
```c
#define T ModuleName_T
typedef struct T *T;  /* Opaque pointer - structure not visible */
```

### Implementation (Private):
```c
#define T ModuleName_T

struct T {
    /* Actual structure definition - not in header */
    int field1;
    size_t field2;
};
```

**Benefits**:
- Encapsulation - internal structure hidden
- ABI stability - can change structure without recompiling clients
- Type safety - can't accidentally use wrong type

## T Macro Pattern

### Purpose:
- Reduces typing
- Consistent naming
- Easy to change if needed

### Usage:
```c
/* Define at top of file */
#define T ModuleName_T

/* Use throughout file */
T instance;
static void helper(T obj);
T function(T param);

/* Undefine at end of file */
#undef T
```

## Module Prefix Pattern

All public identifiers must be prefixed with module name:

### Types:
- `Socket_T`, `SocketBuf_T`, `SocketPoll_T`

### Functions:
- `Socket_bind()`, `Socket_connect()`, `Socket_send()`
- `SocketPoll_new()`, `SocketPoll_wait()`, `SocketPoll_free()`

### Constants:
- `SOCKET_MAX_SIZE`, `SOCKET_DEFAULT_TIMEOUT`

### Exceptions:
- `Socket_Failed`, `SocketPoll_Failed`

**Benefits**:
- No name collisions
- Clear ownership of APIs
- Easy to grep/search

## Private Header Pattern

For split-file modules (e.g., SocketPool, SocketTLSContext):

### Public Header (`ModuleName.h`):
```c
/* Only public API exposed */
extern T ModuleName_new(void);
extern void ModuleName_free(T *instance);
```

### Private Header (`ModuleName-private.h`):
```c
/* Internal structures and helpers for split files */
struct T {
    /* Internal structure */
};

/* Internal helper functions */
extern void modulename_internal_helper(T instance);
```

**Rules**:
- Private headers not installed with public headers
- Only used by implementation files in the module
- Contains internal structures and helper APIs

## File Splitting Pattern

For large modules (> 2000 lines), follow these patterns:

### SocketPool Pattern:
- `SocketPool-core.c` - Creation/destruction, configuration
- `SocketPool-connections.c` - Connection add/remove
- `SocketPool-ops.c` - Connection operations
- `SocketPool-drain.c` - Graceful shutdown

### SocketTLSContext Pattern:
- `SocketTLSContext-core.c` - Core context lifecycle
- `SocketTLSContext-certs.c` - Certificate/key loading
- `SocketTLSContext-alpn.c` - ALPN negotiation
- `SocketTLSContext-session.c` - Session resumption

### Pattern:
- Single public header (`ModuleName.h`)
- Private header (`ModuleName-private.h`) for internal communication
- Multiple implementation files (`ModuleName-*.c`)
- Each file serves single purpose

## Consistency Checklist

Before committing code, verify:

### Header Files:
- [ ] Include guard uses `_INCLUDED` suffix
- [ ] System headers before project headers
- [ ] Module documentation at top
- [ ] Type definitions use `T` macro pattern
- [ ] Function declarations use `extern` keyword
- [ ] Doxygen-style documentation for all functions
- [ ] `#undef T` at end before `#endif`
- [ ] No structure definitions exposed (opaque types only)

### Implementation Files:
- [ ] Module documentation comment at top
- [ ] `/* Part of the Socket Library */` comment
- [ ] `/* Following C Interfaces and Implementations patterns */` comment
- [ ] System headers before project headers
- [ ] `#define T ModuleName_T` at top
- [ ] Static helper functions before public functions
- [ ] Return types on separate lines (GNU C style)
- [ ] Doxygen-style comments for all functions (public and static)
- [ ] `#undef T` at end
- [ ] No trailing whitespace

### Naming:
- [ ] Public types use `ModuleName_T` pattern
- [ ] Public functions use `Module_Verb` pattern
- [ ] Private functions use `lower_snake_case`
- [ ] Constants use `MODULE_NAME` or `SOCKET_MODULE_NAME`
- [ ] Exceptions use `Module_ErrorType` pattern

### Formatting:
- [ ] 8-space indentation
- [ ] Return type on separate line for function definitions
- [ ] Space after `if`, `while`, `for`, `switch`
- [ ] Space around operators
- [ ] No space before semicolon
- [ ] Pointer alignment: `type *ptr` not `type* ptr`
- [ ] Opening brace on same line
- [ ] Consistent spacing in function calls

### Documentation:
- [ ] All public functions have Doxygen comments
- [ ] Parameters documented with `@param`
- [ ] Return values documented with `Returns:`
- [ ] Exceptions documented with `Raises:`
- [ ] Thread safety noted where applicable
- [ ] Comments explain WHY, not WHAT

### Code Organization:
- [ ] Static helpers before public functions
- [ ] Related functions grouped together
- [ ] Include dependencies minimized
- [ ] File serves single purpose
- [ ] Large files split following established patterns
