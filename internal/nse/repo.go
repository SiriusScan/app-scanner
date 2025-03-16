package nse

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitOperations defines the interface for Git operations
type GitOperations interface {
	Clone(repoURL, targetPath string) error
	Fetch(repoPath string) error
	Reset(repoPath string) error
}

// DefaultGitOps implements GitOperations using real Git commands
type DefaultGitOps struct{}

func (g *DefaultGitOps) Clone(repoURL, targetPath string) error {
	cmd := exec.Command("git", "clone", repoURL, targetPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to clone repository: %s: %w", output, err)
	}
	return nil
}

func (g *DefaultGitOps) Fetch(repoPath string) error {
	cmd := exec.Command("git", "fetch", "origin")
	cmd.Dir = repoPath
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to fetch repository: %s: %w", output, err)
	}
	return nil
}

func (g *DefaultGitOps) Reset(repoPath string) error {
	cmd := exec.Command("git", "reset", "--hard", "origin/main")
	cmd.Dir = repoPath
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reset repository: %s: %w", output, err)
	}
	return nil
}

// RepoManager handles NSE script repository operations
type RepoManager struct {
	BasePath string
	RepoURL  string
	gitOps   GitOperations
}

// NewRepoManager creates a new RepoManager instance
func NewRepoManager(basePath string, repoURL string) *RepoManager {
	return &RepoManager{
		BasePath: basePath,
		RepoURL:  repoURL,
		gitOps:   &DefaultGitOps{},
	}
}

// SetGitOps sets the GitOperations implementation (useful for testing)
func (rm *RepoManager) SetGitOps(gitOps GitOperations) {
	rm.gitOps = gitOps
}

// EnsureRepo ensures the repository exists and is up to date
func (r *RepoManager) EnsureRepo() error {
	// Check if repository exists
	if !r.isGitRepo() {
		// Clone repository if it doesn't exist
		log.Printf("Cloning repository to %s", r.BasePath)
		if err := r.gitOps.Clone(r.RepoURL, r.BasePath); err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}
	} else {
		// Update existing repository
		log.Printf("Updating repository at %s", r.BasePath)
		if err := r.updateRepo(); err != nil {
			return fmt.Errorf("failed to update repository: %w", err)
		}
	}

	return nil
}

// isGitRepo checks if the directory is a Git repository
func (rm *RepoManager) isGitRepo() bool {
	gitDir := filepath.Join(rm.BasePath, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		return false
	}
	return true
}

// updateRepo updates the NSE script repository
func (rm *RepoManager) updateRepo() error {
	log.Printf("Updating NSE script repository at %s", rm.BasePath)

	// Fetch latest changes
	fmt.Println("📥 Fetching latest changes from remote repository...")
	if err := rm.gitOps.Fetch(rm.BasePath); err != nil {
		return fmt.Errorf("failed to fetch repository: %w", err)
	}

	// Check if there are updates
	cmd := exec.Command("git", "rev-list", "--count", "HEAD..origin/main")
	cmd.Dir = rm.BasePath
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to check for updates: %v\n", err)
	} else {
		count := strings.TrimSpace(string(output))
		if count != "0" {
			fmt.Printf("🆕 New changes detected! %s commit(s) to pull\n", count)
		} else {
			fmt.Println("✅ Repository already up to date")
		}
	}

	// Reset to origin/main
	fmt.Println("🔄 Resetting to latest remote version...")
	if err := rm.gitOps.Reset(rm.BasePath); err != nil {
		return fmt.Errorf("failed to reset repository: %w", err)
	}

	fmt.Println("✅ Repository successfully updated")
	return nil
}

// GetManifest returns the current manifest from the repository
func (rm *RepoManager) GetManifest() (*Manifest, error) {
	manifestPath := filepath.Join(rm.BasePath, ManifestFile)
	return LoadManifest(manifestPath)
}
