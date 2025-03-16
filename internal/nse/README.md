# NSE (Nmap Script Engine) Package

This package manages NSE scripts in the Sirius Scanner, providing a robust synchronization system between local scripts, a global ValKey store, and Git repositories. The system ensures consistent script management across Docker containers while maintaining script integrity and version control.

## Core Components

### 1. Directory Structure

```
/opt/sirius/nse/               # Base directory in Docker
├── manifest.json            # Repository list manifest
├── sirius-nse/             # Repository directory
│   ├── manifest.json      # Repository manifest
│   └── scripts/          # NSE scripts directory
│       └── vulners.nse  # Example script
```

### 2. Manifest System

The NSE system uses several types of manifests that work together:

1. **Repository List Manifest** (`manifest.json`)

   - Lists all NSE script repositories
   - Example:

   ```json
   {
     "repositories": [
       {
         "name": "sirius-nse",
         "url": "https://github.com/SiriusScan/sirius-nse.git"
       }
     ]
   }
   ```

2. **Repository Manifest** (`<repo>/manifest.json`)

   - Source of truth for script definitions
   - Contains script metadata and paths
   - Example:

   ```json
   {
     "name": "sirius-nse",
     "version": "0.1.0",
     "description": "NSE scripts for Sirius",
     "scripts": {
       "vulners": {
         "name": "vulners",
         "path": "scripts/vulners.nse",
         "protocol": "*"
       }
     }
   }
   ```

3. **Global Manifests** (ValKey)

   - `nse:repo-manifest` - Global repository list
   - `nse:manifest` - Global script manifest
   - Take precedence over local manifests
   - Enable cross-container synchronization

4. **Local Manifests** (Memory)
   - Working copies in each container
   - Synchronized with global manifests
   - Used for script execution

### 3. Synchronization System

The sync system follows a priority-based approach:

```
Global ValKey > Local Files > Built-in Defaults
```

Key features:

- Automatic initialization of empty manifests
- Built-in repository list as fallback
- Preservation of script content during syncs
- Proper error handling for missing scripts
- Atomic updates to prevent partial states

### 4. ValKey Integration

Key naming convention:

- `nse:repo-manifest` - Global repository list storage
- `nse:manifest` - Global script manifest storage
- `nse:script:<script_name>` - Script content storage

## Usage

### Basic Initialization

```go
// Create a repo manager with Docker path
repoManager := nse.NewRepoManager("/opt/sirius/nse/sirius-nse", repoURL)

// Create a sync manager
syncManager := nse.NewSyncManager(repoManager, kvStore)

// Synchronize repositories and scripts
err := syncManager.Sync(context.Background())
```

### Script Content Management

```go
// Update script content
err := syncManager.updateScriptContent(ctx, "vulners", &ScriptContent{
    Content: scriptContent,
    Metadata: Metadata{
        Author:      "Author Name",
        Tags:        []string{"vulnerability"},
        Description: "Script description",
    },
    UpdatedAt: time.Now().Unix(),
})
```

## Error Handling

The system implements comprehensive error handling:

1. **ValKey Errors**

   - Handles "nil message" errors for missing keys
   - Provides initialization for missing manifests
   - Preserves error context through wrapping

2. **File System Errors**

   - Handles missing directories
   - Manages file permissions
   - Provides cleanup for legacy paths

3. **Repository Errors**

   - Graceful handling of repository failures
   - Continues processing other repositories on error
   - Clear error messages for troubleshooting

4. **Synchronization Errors**
   - Graceful handling of missing scripts
   - Clear error messages for troubleshooting
   - Proper context preservation

## Testing

Run the NSE test program to verify the setup:

```bash
docker exec -it sirius-engine go run cmd/nse-test/main.go
```

The test program:

- Verifies ValKey connectivity
- Tests repository manifest synchronization
- Tests script manifest synchronization
- Validates script content management
- Checks directory structure
- Cleans up legacy paths

## Best Practices

1. **Docker Environment**

   - Always use `/opt/sirius/nse` as the base path
   - Ensure proper permissions (755 for directories)
   - Clean up legacy directories when found

2. **Repository Management**

   - Use the built-in repository list as a fallback
   - Let ValKey repository manifest take precedence
   - Handle repository failures gracefully

3. **Manifest Management**

   - Let global manifests take precedence
   - Initialize empty manifests when missing
   - Preserve script metadata during syncs

4. **Error Handling**

   - Check ValKey connectivity first
   - Validate paths before operations
   - Log meaningful error messages

5. **Synchronization**
   - Always sync before script execution
   - Verify script content after updates
   - Handle missing scripts gracefully
