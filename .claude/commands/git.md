# Git Operations Command

Automate git operations for code changes including staging, committing, and pushing modifications.

## Primary Workflow

When requested to "commit changes" or "do git stuff", perform the following:

### 1. **Status Check**
   - Run `git status --short` to see current state
   - Identify modified files (M)
   - Identify untracked files (??)
   - Identify deleted files (D)
   - Check if there are already staged changes

### 2. **Staging Files**
   - Stage all modified files: `git add <file>`
   - Stage all untracked source files (`.c`, `.h` files)
   - Skip staging temporary files, build artifacts, or IDE-specific files:
     - `.o` files
     - `*.swp`, `*.swo`
     - `.cursor/` directory (unless explicitly requested)
     - Build directories
   - For most operations, stage source code files only

### 3. **Commit Message Generation**
   Generate meaningful commit messages based on:
   - **File changes**: Analyze what files were modified
   - **Code changes**: Review the actual diff to understand what changed
   - **Functionality**: Determine if it's a bug fix, feature, refactor, or style change
   
   Commit message format:
   ```
   <type>: <brief description>
   
   <detailed explanation if needed>
   ```
   
   Types:
   - `fix`: Bug fixes
   - `feat`: New features
   - `refactor`: Code restructuring without behavior change
   - `style`: Code style/formatting changes (indentation, spacing, etc.)
   - `docs`: Documentation changes
   - `perf`: Performance improvements
   - `test`: Test additions/changes
   - `chore`: Maintenance tasks

### 4. **Commit Execution**
   - Create commit with generated message: `git commit -m "<message>"`
   - If commit fails, provide error details and suggest fixes

### 5. **Optional Push**
   - Only push if explicitly requested
   - Check if remote is configured: `git remote -v`
   - Push to current branch: `git push`
   - If push fails, report error and suggest resolution

## Command Variations

### Basic Commit
When user says "commit changes" or "git commit":
- Stage all modified source files
- Generate commit message from changes
- Create commit
- Show commit summary

### Commit Specific Files
When user specifies files:
- Stage only those files: `git add <file1> <file2>`
- Generate message focused on those changes
- Create commit

### Commit with Custom Message
When user provides a message:
- Use provided message exactly
- Stage appropriate files
- Create commit

### Full Workflow (Stage + Commit + Push)
When user says "do all git stuff" or "commit and push":
- Stage files
- Commit with message
- Push to remote
- Report final status

## Error Handling

### Pre-commit Checks
- Verify we're in a git repository: `git rev-parse --git-dir`
- Check if there are changes to commit
- Warn if committing with uncommitted changes (if applicable)
- Check for merge conflicts

### Common Issues
- **No changes**: Report "No changes to commit"
- **Nothing staged**: Auto-stage source files before committing
- **Merge conflicts**: Report conflicts and suggest resolution
- **Authentication issues**: Suggest checking credentials/SSH keys
- **Upstream divergence**: Suggest `git pull` or `git pull --rebase`

## Git Status Analysis

When analyzing git status:
- Read the actual file diffs to understand changes
- Group related changes together
- Identify the primary purpose of changes (bug fix, feature, refactor)
- Detect if changes follow project coding standards

## Example Workflows

### Example 1: Simple Code Fix
```
Status: M file_io.c
Analysis: Fixed memory leak in error path
Action: git add file_io.c && git commit -m "fix: memory leak in file_io error handling"
```

### Example 2: Multiple Related Changes
```
Status: M main.c M parse_gadgets.c M file_io.h
Analysis: Refactored error handling across multiple files
Action: git add main.c parse_gadgets.c file_io.h && git commit -m "refactor: improve error handling consistency"
```

### Example 3: Feature Addition
```
Status: M main.c ?? new_feature.c ?? new_feature.h
Analysis: Added new feature for gadget filtering
Action: git add main.c new_feature.c new_feature.h && git commit -m "feat: add gadget filtering functionality"
```

## Best Practices

1. **Always review changes** before committing
2. **Group related changes** in single commits
3. **Write clear commit messages** that explain what and why
4. **Don't auto-push** unless explicitly requested
5. **Preserve user's workflow** - don't force rebase or other advanced operations
6. **Respect .gitignore** - don't stage ignored files
7. **Check for sensitive data** before committing (API keys, passwords, etc.)

## Interactive Mode

If the user's intent is unclear:
- Show git status
- List files that would be staged
- Ask for confirmation before committing
- Suggest commit message and ask for approval

## Output Format

After git operations, provide:
- Summary of what was staged
- Commit message used
- Commit hash (if successful)
- Push status (if pushed)
- Any warnings or errors

