#!/bin/bash

# Script to add @brief tags to function documentation that doesn't have them

for file in include/*.h include/*/*.h; do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    
    echo "Processing $file..."
    
    # Use awk to process the file and add @brief tags
    awk '
    BEGIN { in_comment = 0; in_function_doc = 0; function_name = "" }
    
    /^\/\*\*$/ { 
        in_comment = 1
        in_function_doc = 0
        function_name = ""
        comment_lines = ""
    }
    
    in_comment && /^ \*[[:space:]]*([A-Z][a-zA-Z_]+)[[:space:]]*-/ {
        # Found a function documentation line like "FunctionName - description"
        match($0, /^[[:space:]]*\*[[:space:]]*([A-Z][a-zA-Z0-9_]+)[[:space:]]*-/, arr)
        if (arr[1]) {
            function_name = arr[1]
            in_function_doc = 1
        }
    }
    
    in_comment && /^ \*\// {
        # End of comment block
        if (in_function_doc && function_name != "" && comment_lines !~ /@brief/) {
            # This is a function doc without @brief - add it
            # Find the first line after /** that has content
            split(comment_lines, lines, "\n")
            for (i = 1; i <= length(lines); i++) {
                if (lines[i] ~ /^[[:space:]]*\*[[:space:]]*[A-Z]/ && lines[i] !~ /@/) {
                    # Insert @brief before this line
                    sub(/^[[:space:]]*\*/, " * @brief", lines[i])
                    break
                }
            }
            # Reconstruct comment_lines
            comment_lines = ""
            for (i = 1; i <= length(lines); i++) {
                if (comment_lines != "") comment_lines = comment_lines "\n"
                comment_lines = comment_lines lines[i]
            }
        }
        in_comment = 0
        in_function_doc = 0
        function_name = ""
    }
    
    in_comment {
        # Accumulate comment lines
        if (comment_lines != "") comment_lines = comment_lines "\n"
        comment_lines = comment_lines $0
    }
    
    { print }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    
done

echo "Done processing all header files."
