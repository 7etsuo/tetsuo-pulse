#!/bin/bash

echo "Cleaning up documentation tags..."

for file in include/socket/*.h include/dns/*.h include/poll/*.h include/pool/*.h; do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    
    echo "Cleaning $file..."
    
    # Remove duplicate @brief and @ingroup tags
    sed -i '/^[[:space:]]*@brief.*@brief/d' "$file"
    sed -i '/^[[:space:]]*@ingroup.*@ingroup/d' "$file"
    
    # Fix malformed tags
    sed -i 's/@brief Thread-safe:/@note Thread-safe:/g' "$file"
    sed -i 's/@brief Returns:/@return/g' "$file"
    sed -i 's/@brief Raises:/@throws/g' "$file"
    sed -i 's/@brief Note:/@note/g' "$file"
    
    # Fix parameter formatting
    sed -i 's/@brief @/ *@param /g' "$file"
    
done

echo "Cleanup complete!"
