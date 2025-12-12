#!/bin/bash
# Add SPDX license headers to all .c and .h files

LICENSE_HEADER='/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

'

add_header() {
    local file="$1"
    # Check if file already has SPDX header
    if grep -q "SPDX-License-Identifier" "$file"; then
        echo "SKIP: $file (already has license)"
        return
    fi
    
    # Create temp file with header + original content
    echo -n "$LICENSE_HEADER" > "$file.tmp"
    cat "$file" >> "$file.tmp"
    mv "$file.tmp" "$file"
    echo "ADDED: $file"
}

export -f add_header
export LICENSE_HEADER

# Process all .c files in src/
find src -name '*.c' -type f | while read file; do
    add_header "$file"
done

# Process all .h files in include/
find include -name '*.h' -type f | while read file; do
    add_header "$file"
done

# Process example .c files
find examples -name '*.c' -type f | while read file; do
    add_header "$file"
done

echo ""
echo "Done! Verifying..."
echo "Files with SPDX header:"
grep -r "SPDX-License-Identifier" src include examples --include="*.c" --include="*.h" | wc -l
