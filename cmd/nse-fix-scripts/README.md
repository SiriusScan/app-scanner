# NSE Script Format Fixer

This tool fixes incorrectly formatted NSE scripts by extracting Lua code from JSON wrappers.

## Purpose

The NSE Script Format Fixer addresses an issue where NSE scripts are stored in JSON format in ValKey but need to be in Lua format for Nmap execution. It:

- Scans all NSE scripts in the repository
- Identifies scripts stored in JSON format with a "content" field
- Extracts the Lua code from the JSON wrapper
- Rewrites the script files with the correct Lua content
- Ensures all scripts are in the correct format for Nmap execution

## Usage

### In Docker Container

```bash
# Run the fixer
docker exec -it sirius-engine go run cmd/nse-fix-scripts/main.go
```

### Locally

```bash
# Run the fixer
go run cmd/nse-fix-scripts/main.go
```

## When to Use

Use this tool when:

1. You encounter the "unexpected symbol near '{'" error with Nmap scripts
2. Nmap fails to run scripts with JSON parsing errors
3. After adding new scripts to the repository
4. After running the NSE reset tool and scripts are still not working

## How It Works

The fixer:

1. Scans all .nse files in the repository directory
2. Checks if each file starts with a JSON brace `{`
3. If JSON, attempts to parse and extract the "content" field
4. Replaces the file with the extracted Lua content
5. Leaves properly formatted Lua scripts untouched

## Output

The tool provides detailed feedback:

- 🔧 Starting the fixer
- 🔍 Directory being scanned
- 📦 Files detected as JSON format
- ✅ Successfully fixed scripts
- ⚠️ Errors during fixing process

## Error Handling

The fixer handles:

- Missing directories
- Invalid JSON format
- Missing content field
- File read/write errors

## After Running

After running the fixer, you should:

1. Try running Nmap with the fixed scripts
2. Test scripts with the NSE scan test utility
3. Verify that all scripts execute correctly

## See Also

- [NSE Reset](../nse-reset/README.md) - For resetting the ValKey manifest
- [NSE Scan Test](../nse-scan-test/README.md) - For testing the fixed scripts
