package core

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/macophub/macop/envconfig"
)

type MCPPath struct {
	ProtocolScheme string
	Registry       string
	Namespace      string
	Repository     string
	Tag            string
}

const (
	DefaultRegistry       = "registry-1.docker.io"
	DefaultNamespace      = "library"
	DefaultTag            = "latest"
	DefaultProtocolScheme = "https"
)

var (
	ErrInvalidImageFormat  = errors.New("invalid image format")
	ErrInvalidDigestFormat = errors.New("invalid digest format")
	ErrInvalidProtocol     = errors.New("invalid protocol scheme")
	ErrInsecureProtocol    = errors.New("insecure protocol http")
	ErrModelPathInvalid    = errors.New("invalid model path")
)

func ParseMCPPath(name string) MCPPath {
	mp := MCPPath{
		ProtocolScheme: DefaultProtocolScheme,
		Registry:       DefaultRegistry,
		Namespace:      DefaultNamespace,
		Repository:     "",
		Tag:            DefaultTag,
	}

	before, after, found := strings.Cut(name, "://")
	if found {
		mp.ProtocolScheme = before
		name = after
	}

	name = strings.ReplaceAll(name, string(os.PathSeparator), "/")
	parts := strings.Split(name, "/")
	switch len(parts) {
	case 3:
		mp.Registry = parts[0]
		mp.Namespace = parts[1]
		mp.Repository = parts[2]
	case 2:
		mp.Namespace = parts[0]
		mp.Repository = parts[1]
	case 1:
		mp.Repository = parts[0]
	}

	if repo, tag, found := strings.Cut(mp.Repository, ":"); found {
		mp.Repository = repo
		mp.Tag = tag
	}

	return mp
}

func (mp MCPPath) GetNamespaceRepository() string {
	return fmt.Sprintf("%s/%s", mp.Namespace, mp.Repository)
}

func (mp MCPPath) GetFullTagname() string {
	return fmt.Sprintf("%s/%s/%s:%s", mp.Registry, mp.Namespace, mp.Repository, mp.Tag)
}

func (mp MCPPath) GetShortTagname() string {
	if mp.Registry == DefaultRegistry {
		if mp.Namespace == DefaultNamespace {
			return fmt.Sprintf("%s:%s", mp.Repository, mp.Tag)
		}
		return fmt.Sprintf("%s/%s:%s", mp.Namespace, mp.Repository, mp.Tag)
	}
	return fmt.Sprintf("%s/%s/%s:%s", mp.Registry, mp.Namespace, mp.Repository, mp.Tag)
}

// GetManifestPath returns the path to the manifest file for the given model path, it is up to the caller to create the directory if it does not exist.
func (mp MCPPath) GetManifestPath() (string, error) {
	name := Name{
		Host:      mp.Registry,
		Namespace: mp.Namespace,
		Model:     mp.Repository,
		Tag:       mp.Tag,
	}
	if !name.IsValid() {
		return "", fs.ErrNotExist
	}
	return filepath.Join(envconfig.McpPath(), "manifests", name.Filepath()), nil
}

// GetRunPath returns the path to the manifest file for the given model path, it is up to the caller to create the directory if it does not exist.
func (mp MCPPath) GetRunPath() (string, error) {
	name := Name{
		Host:      mp.Registry,
		Namespace: mp.Namespace,
		Model:     mp.Repository,
		Tag:       mp.Tag,
	}
	if !name.IsValid() {
		return "", fs.ErrNotExist
	}
	return filepath.Join(envconfig.McpPath(), "run", name.Filepath()), nil
}

func (mp MCPPath) BaseURL() *url.URL {
	return &url.URL{
		Scheme: mp.ProtocolScheme,
		Host:   mp.Registry,
	}
}

func GetManifestPath() (string, error) {
	path := filepath.Join(envconfig.McpPath(), "manifests")
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", err
	}

	return path, nil
}

func GetManifestListPath() (string, error) {
	path := filepath.Join(envconfig.McpPath(), "manifests")
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", err
	}

	return path, nil
}

func GetBlobsPath(digest string) (string, error) {
	// only accept actual sha256 digests
	pattern := "^sha256[:-][0-9a-fA-F]{64}$"
	re := regexp.MustCompile(pattern)

	if digest != "" && !re.MatchString(digest) {
		return "", ErrInvalidDigestFormat
	}

	digest = strings.ReplaceAll(digest, ":", "-")
	path := filepath.Join(envconfig.McpPath(), "blobs", digest)
	dirPath := filepath.Dir(path)
	if digest == "" {
		dirPath = path
	}

	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		return "", err
	}

	return path, nil
}
