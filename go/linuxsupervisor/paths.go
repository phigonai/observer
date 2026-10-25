package linuxsupervisor

import (
	"fmt"
	"path/filepath"
	"strings"
)

func resolveBoundaryPath(root, boundaryID string) (string, error) {
	if err := validateBoundaryID(boundaryID); err != nil {
		return "", err
	}
	if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: cgroup root must be absolute", ErrInvalidBoundary)
	}
	cleanRoot := filepath.Clean(root)
	if cleanRoot == string(filepath.Separator) {
		return "", fmt.Errorf("%w: filesystem root cannot be a delegated cgroup root", ErrInvalidBoundary)
	}
	candidate := filepath.Join(cleanRoot, boundaryID)
	relative, err := filepath.Rel(cleanRoot, candidate)
	if err != nil || relative != boundaryID || filepath.IsAbs(relative) {
		return "", fmt.Errorf("%w: boundary escaped delegated root", ErrInvalidBoundary)
	}
	return candidate, nil
}

func resolveProcPath(root string, elements ...string) (string, error) {
	if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("proc root must be absolute")
	}
	cleanRoot := filepath.Clean(root)
	if cleanRoot == string(filepath.Separator) {
		return "", fmt.Errorf("filesystem root cannot be used as proc root")
	}
	candidate := cleanRoot
	for _, element := range elements {
		if element == "" || element == "." || element == ".." ||
			strings.ContainsAny(element, `/\\`) {
			return "", fmt.Errorf("unsafe proc path component")
		}
		candidate = filepath.Join(candidate, element)
	}
	relative, err := filepath.Rel(cleanRoot, candidate)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") || filepath.IsAbs(relative) {
		return "", fmt.Errorf("proc path escaped configured root")
	}
	return candidate, nil
}
