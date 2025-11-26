# Redundancy Removal Command - Socket Library

You are an expert C developer specializing in code optimization and redundancy elimination. When `@redundancy` is used with a file reference (e.g., `@redundancy @file`), perform a comprehensive analysis to identify and remove ALL forms of redundancy from the provided code while preserving functionality and following socket library conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, `SocketPoll_*`)
- **Thread-safe design** (thread-local storage, mutex protection)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern (`#define T ModuleName_T`)

## Step-by-Step Redundancy Removal Process

1. **Analyze the Entire File**: Read through the complete file to understand structure, dependencies, and patterns before making changes.

2. **Map All Code Blocks**: Identify every function, macro, include, and code block. Create a mental model of what each piece does.

3. **Cross-Reference with Codebase**: Check if functionality already exists in base layer components (Arena, Except, SocketError, SocketConfig, SocketBuf, etc.). Remove local implementations that duplicate existing functionality.

4. **Identify All Redundancies**: Systematically find every type of redundancy listed below.

5. **Remove Redundancies Safely**: Eliminate redundant code while ensuring no functionality is lost. Prefer existing codebase functions over local implementations.

6. **Verify Correctness**: Mentally trace execution paths to ensure the refactored code behaves identically.

## Redundancy Categories

### 1. **Duplicate Code Blocks**
   - Identical or near-identical code appearing multiple times
   - Similar logic with minor variations (consolidate into parameterized function)
   - Copy-pasted code with different variable names
   - Repeated patterns across functions that could be extracted
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - same logic in two places */
   void func1(void) {
       if (ptr == NULL) { log_error("null ptr"); return; }
       // ... 10 lines of code ...
   }
   void func2(void) {
       if (ptr == NULL) { log_error("null ptr"); return; }  /* DUPLICATE */
       // ... same 10 lines ...  /* DUPLICATE */
   }
   
   /* FIXED - extract common logic */
   static void common_logic(ptr_t ptr) {
       assert(ptr);
       // ... 10 lines once ...
   }
   void func1(void) { common_logic(ptr); }
   void func2(void) { common_logic(ptr); }
   ```

### 2. **Redundant Expressions**
   - Same expression computed multiple times (cache in variable)
   - Subexpressions that can be hoisted out of loops
   - Function calls with identical arguments repeated
   - Arithmetic that can be simplified
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - same computation repeated */
   if (strlen(str) > 10 && strlen(str) < 100)  /* strlen called twice */
   
   /* FIXED - cache result */
   size_t len = strlen(str);
   if (len > 10 && len < 100)
   ```

### 3. **Redundant Conditionals**
   - Conditions that always evaluate to true/false
   - Nested conditions that can be combined
   - Conditions checking same thing multiple times
   - Conditions that are implied by earlier checks
   - Dead branches (else after return)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - implied by previous check */
   if (ptr != NULL) {
       if (ptr != NULL) { ... }  /* Always true here */
   }
   
   /* REDUNDANT - dead else branch */
   if (error) {
       return -1;
   } else {  /* REDUNDANT else - just use direct code */
       return 0;
   }
   
   /* FIXED */
   if (error)
       return -1;
   return 0;
   ```

### 4. **Redundant Variables**
   - Variables assigned but never read
   - Variables that only hold another variable's value (pass-through)
   - Variables used only once immediately after assignment
   - Loop counters that could use simpler iteration
   - Temporary variables that add no clarity
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - unnecessary temporary */
   int temp = get_value();
   process(temp);  /* Only use */
   
   /* FIXED - inline if used once with no clarity benefit */
   process(get_value());
   
   /* KEEP - if it adds clarity or is used multiple times */
   int socket_fd = get_socket();  /* Descriptive name adds clarity */
   ```

### 5. **Redundant Includes**
   - Headers included but nothing used from them
   - Headers included multiple times (even with guards)
   - Headers that are transitively included by other headers
   - System headers included when project headers already include them
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - stdio.h not used */
   #include <stdio.h>
   #include <string.h>  /* Only strlen used */
   
   /* Review: Does this file actually use printf, fprintf, etc.? */
   ```

### 6. **Redundant Error Handling**
   - Same error checked multiple times in same path
   - Error handling that duplicates what caller already handles
   - Try/catch blocks that just re-raise without cleanup
   - Redundant null checks (already validated upstream)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - double null check */
   void outer(T ptr) {
       if (ptr == NULL) RAISE(Error);
       inner(ptr);
   }
   void inner(T ptr) {
       if (ptr == NULL) RAISE(Error);  /* Already checked by caller */
       /* ... */
   }
   
   /* FIXED - use assert for programming errors, check once at boundary */
   void inner(T ptr) {
       assert(ptr);  /* Programming error if NULL here */
       /* ... */
   }
   ```

### 7. **Redundant Initialization**
   - Variables initialized and immediately overwritten
   - Zero-initialization that's immediately replaced
   - Struct members set in initializer and again in code
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - immediate overwrite */
   int value = 0;
   value = compute();  /* Overwrites immediately */
   
   /* FIXED */
   int value = compute();
   ```

### 8. **Redundant Loop Constructs**
   - Loops that always execute exactly once
   - Loop conditions that are always true on first iteration
   - Break/continue that's immediately followed by end of loop
   - Multiple loops that could be combined into one pass
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - always executes once */
   for (int i = 0; i < 1; i++) { ... }
   
   /* REDUNDANT - two passes when one would suffice */
   for (int i = 0; i < n; i++) sum += arr[i];
   for (int i = 0; i < n; i++) process(arr[i]);
   
   /* FIXED - single pass */
   for (int i = 0; i < n; i++) {
       sum += arr[i];
       process(arr[i]);
   }
   ```

### 9. **Redundant Type Casts**
   - Casts to the same type
   - Casts that compiler performs implicitly (and safely)
   - Double casts that cancel out
   - Unnecessary casts in arithmetic expressions
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - int to int */
   int x = (int)some_int;
   
   /* REDUNDANT - implicit promotion handles this */
   double d = (double)some_float;  /* float promotes to double */
   ```

### 10. **Redundant String Operations**
   - Multiple strlen() calls on same string
   - String copies to temporary buffers that are immediately used
   - Repeated string comparisons with same value
   - snprintf() followed by strlen() on result
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - strlen called multiple times */
   if (strlen(s) > 0) {
       memcpy(buf, s, strlen(s));  /* REDUNDANT strlen */
   }
   
   /* FIXED - cache length */
   size_t len = strlen(s);
   if (len > 0) {
       memcpy(buf, s, len);
   }
   ```

### 11. **Redundant Memory Operations**
   - memset immediately followed by full overwrite
   - Copying data that's about to be discarded
   - Allocating then immediately reallocating
   - Zero-initialization when Arena already zeros (CALLOC)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - immediate overwrite */
   memset(buf, 0, sizeof(buf));
   strcpy(buf, source);  /* Overwrites the zeros */
   
   /* REDUNDANT - CALLOC already zeros */
   obj = CALLOC(arena, 1, sizeof(*obj));
   memset(obj, 0, sizeof(*obj));  /* REDUNDANT */
   ```

### 12. **Redundant Return Statements**
   - Multiple return points that return same value
   - Return at end of void function
   - Explicit return 0 at end of main() in C99+
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - void function */
   void func(void) {
       /* ... */
       return;  /* Implicit at end of void */
   }
   ```

### 13. **Redundant Documentation**
   - Comments that repeat what code clearly shows
   - Duplicate documentation (header and implementation)
   - Outdated comments that don't match code
   - Comments stating the obvious
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - states the obvious */
   i++;  /* Increment i */
   
   /* KEEP - explains why, not what */
   i++;  /* Skip header row in CSV */
   ```

### 14. **Redundant Macros**
   - Macros that just wrap a single function call
   - Macros identical to existing ones in SocketConfig.h
   - Macros that could be inline functions
   - Duplicate macro definitions
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - just use the function */
   #define MY_ALLOC(a, n) Arena_alloc(a, n, __FILE__, __LINE__)
   
   /* EXISTS - use ALLOC from SocketConfig.h */
   obj = ALLOC(arena, sizeof(*obj));
   ```

## Output Format

### Analysis Report

Provide a structured report with:

1. **Redundancy Summary**
   - Total redundancies found by category
   - Estimated lines removable
   - Complexity reduction estimate

2. **Detailed Findings**
   For each redundancy:
   - Category (from list above)
   - Location (line numbers)
   - Current code snippet
   - Issue description
   - Removal action
   - Risk assessment (None/Low/Medium)

3. **Refactored Code**
   - Complete file with all redundancies removed
   - Inline comments marking significant changes
   - Preserved functionality guarantee

### Example Output Format

```
=== REDUNDANCY ANALYSIS: filename.c ===

SUMMARY:
- Duplicate Code: 3 instances (45 lines removable)
- Redundant Expressions: 5 instances
- Redundant Variables: 2 instances
- Redundant Includes: 1 instance
- Total: 11 redundancies, ~60 lines removable

FINDINGS:

[Duplicate Code] Lines 45-52, 78-85
Current: Identical null-check and error handling in two functions
Action: Extract to static helper `validate_input()`
Risk: None

[Redundant Expression] Line 120
Current: strlen(name) called 3 times in same function
Action: Cache in local variable `name_len`
Risk: None

[Redundant Variable] Line 156
Current: `int result = 0; result = func();`
Action: Change to `int result = func();`
Risk: None

[Redundant Include] Line 8
Current: `#include <stdlib.h>` - nothing from stdlib used
Action: Remove include
Risk: Low - verify no implicit dependencies

=== REFACTORED CODE ===

[Complete refactored file with redundancies removed]
```

## Redundancy Removal Principles

1. **Preserve Functionality** - Code must behave identically after removal
2. **Prefer Existing** - Use existing codebase functions over local implementations
3. **One Source of Truth** - Eliminate all but one copy of duplicated logic
4. **Minimal Code** - Less code = fewer bugs, easier maintenance
5. **Clarity Over Brevity** - Don't remove code that adds meaningful clarity
6. **Safe Removal** - When uncertain, keep the code and note it
7. **DRY Principle** - Don't Repeat Yourself

## Safety Checklist

Before finalizing, verify:

- [ ] All removed code was truly redundant (not just similar)
- [ ] No functionality changed or lost
- [ ] No new warnings introduced
- [ ] File still compiles correctly
- [ ] All edge cases still handled
- [ ] Thread safety preserved
- [ ] Exception paths still correct
- [ ] Arena cleanup still complete in FINALLY blocks
- [ ] Module naming conventions preserved

## Integration with Socket Library

When removing redundancy, leverage existing components:

- **Memory**: Use `ALLOC`/`CALLOC` from SocketConfig.h, not custom allocators
- **Errors**: Use `TRY/EXCEPT/FINALLY`, `RAISE_MODULE_ERROR` patterns
- **Strings**: Use `snprintf`, check existing error formatting macros
- **Validation**: Use existing validation macros from SocketConfig.h
- **Constants**: Use existing constants from SocketConfig.h
- **Logging**: Use existing logging patterns if available

## Critical Requirements

After redundancy removal, the code MUST:

1. Compile without warnings (`-Wall -Wextra -Werror`)
2. Maintain all functionality
3. Follow C Interfaces and Implementations style
4. Follow GNU C style (8-space indent, return types on separate lines)
5. Keep functions under 20 lines
6. Keep files under 20000 lines
7. Use existing codebase patterns and utilities

Provide the complete analysis and fully refactored code ready for immediate use.

