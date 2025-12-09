#!/bin/bash

# Bulk update script to add @brief and @ingroup tags to function documentation
# This processes all header files systematically

echo "Starting bulk documentation update..."

# Function to determine the correct @ingroup tag based on file path
get_group() {
    local file="$1"
    if [[ "$file" == *"/core/"* ]]; then
        echo "foundation"
    elif [[ "$file" == *"/socket/"* ]]; then
        echo "core_io"
    elif [[ "$file" == *"/poll/"* ]]; then
        echo "event_system"
    elif [[ "$file" == *"/pool/"* ]]; then
        echo "connection_mgmt"
    elif [[ "$file" == *"/tls/"* ]]; then
        echo "security"
    elif [[ "$file" == *"/http/"* ]]; then
        echo "http"
    elif [[ "$file" == *"/dns/"* ]]; then
        echo "core_io"
    else
        echo "utilities"
    fi
}

# Process each header file
for file in include/*.h include/*/*.h; do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    
    echo "Processing $file..."
    
    group=$(get_group "$file")
    
    # Use sed to add @brief and @ingroup tags to function documentation
    # This looks for /** followed by function name and adds the tags
    sed -i '/^[[:space:]]*\/\*\*$/,/^[[:space:]]*\*\// {
        # Inside a comment block
        /^[[:space:]]*\*[[:space:]]*[A-Z][a-zA-Z0-9_]*[[:space:]]*-/ {
            # Found a function documentation line
            # Check if @brief already exists in this comment block
            /@brief/! {
                # Add @brief and @ingroup tags
                s/^\([[:space:]]*\*[[:space:]]*\)\([A-Z][a-zA-Z0-9_]*[[:space:]]*-.*\)$/\1@brief \2\n\1@ingroup '"$group"'/
            }
        }
    }' "$file"
    
    # For functions that have @brief but no @ingroup, add @ingroup
    sed -i '/^[[:space:]]*\/\*\*$/,/^[[:space:]]*\*\// {
        # Inside a comment block
        /@brief/ {
            # Check if @ingroup exists in this comment block
            /@ingroup/! {
                # Add @ingroup after @brief
                s/\(@brief.*\)/\1\n * @ingroup '"$group"'/
            }
        }
    }' "$file"
    
done

echo "Bulk documentation update complete!"
