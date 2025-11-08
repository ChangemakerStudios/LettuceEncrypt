#!/bin/bash
# Script to automatically update PublicAPI.Unshipped.txt with new APIs

set -e

echo "Building project to detect new public APIs..."

# Try to build and capture the output
BUILD_OUTPUT=$(dotnet build src/LettuceEncrypt/LettuceEncrypt.csproj 2>&1 || true)

# Extract RS0016 errors and parse the API signatures
echo "$BUILD_OUTPUT" | grep "error RS0016" | while read -r line; do
    # Extract the symbol name from the error message
    if [[ $line =~ Symbol\ \'([^\']+)\' ]]; then
        symbol="${BASH_REMATCH[1]}"
        echo "Found new API: $symbol"
        
        # Append to PublicAPI.Unshipped.txt if not already there
        if ! grep -Fq "$symbol" src/LettuceEncrypt/PublicAPI.Unshipped.txt; then
            echo "$symbol" >> src/LettuceEncrypt/PublicAPI.Unshipped.txt
            echo "  Added to PublicAPI.Unshipped.txt"
        fi
    fi
done

# Sort the file (keeping #nullable enable at top)
if [ -f src/LettuceEncrypt/PublicAPI.Unshipped.txt ]; then
    (head -n 1 src/LettuceEncrypt/PublicAPI.Unshipped.txt && tail -n +2 src/LettuceEncrypt/PublicAPI.Unshipped.txt | sort -u) > src/LettuceEncrypt/PublicAPI.Unshipped.txt.tmp
    mv src/LettuceEncrypt/PublicAPI.Unshipped.txt.tmp src/LettuceEncrypt/PublicAPI.Unshipped.txt
    echo "PublicAPI.Unshipped.txt has been updated and sorted"
fi

echo "Done! Run 'dotnet build' again to verify."
