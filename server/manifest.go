package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/macophub/macop/types/model"
)

type ManifestKind string

const (
	ManifestKindItem ManifestKind = "application/vnd.docker.distribution.manifest.v2+json"
	ManifestKindList ManifestKind = "application/vnd.docker.distribution.manifest.list.v2+json"
)

type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     ManifestKind `json:"mediaType"`

	// MediaType == ManifestKindItem
	Config Layer   `json:"config,omitempty,omitzero"`
	Layers []Layer `json:"layers,omitempty,omitzero"`

	// MediaType == ManifestKindList
	Manifests []Layer `json:"manifests,omitempty,omitzero"`

	filepath string
	fi       os.FileInfo
	digest   string
}

func (m *Manifest) Size() (size int64) {
	if m.MediaType == ManifestKindItem {
		for _, layer := range append(m.Layers, m.Config) {
			size += layer.Size
		}
	}

	if m.MediaType == ManifestKindList {
		for _, manifest := range m.Manifests {
			size += manifest.Size
		}
	}
	return
}

func (m *Manifest) Remove() error {
	if err := os.Remove(m.filepath); err != nil {
		return err
	}

	manifests, err := GetManifestPath()
	if err != nil {
		return err
	}

	return PruneDirectory(manifests)
}

func (m *Manifest) RemoveLayers() error {
	if m.MediaType == ManifestKindItem {
		for _, layer := range append(m.Layers, m.Config) {
			if layer.Digest != "" {
				if err := layer.Remove(); errors.Is(err, os.ErrNotExist) {
					slog.Debug("layer does not exist", "digest", layer.Digest)
				} else if err != nil {
					return err
				}
			}
		}
	}

	if m.MediaType == ManifestKindList {
		for _, manifest := range m.Manifests {
			err := manifest.Remove()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ParseNamedManifest(n model.Name) (*Manifest, error) {
	if !n.IsFullyQualified() {
		return nil, model.Unqualified(n)
	}

	manifests, err := GetManifestPath()
	if err != nil {
		return nil, err
	}

	p := filepath.Join(manifests, n.Filepath())
	var m Manifest
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	sha256sum := sha256.New()
	if err := json.NewDecoder(io.TeeReader(f, sha256sum)).Decode(&m); err != nil {
		return nil, err
	}

	m.filepath = p
	m.fi = fi
	m.digest = hex.EncodeToString(sha256sum.Sum(nil))

	return &m, nil
}

func WriteManifest(name model.Name, config Layer, layers []Layer) (*Manifest, error) {
	manifests, err := GetManifestPath()
	if err != nil {
		return nil, err
	}

	p := filepath.Join(manifests, name.Filepath())
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}

	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := Manifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		Config:        config,
		Layers:        layers,
	}

	return &m, json.NewEncoder(f).Encode(m)
}

func WriteManifestList(name model.Name, manifests []*Manifest) (*Manifest, error) {
	manifestListPath, err := GetManifestListPath()
	if err != nil {
		return nil, err
	}

	p := filepath.Join(manifestListPath, name.Filepath())
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}

	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	manifestConfigs := make([]Layer, 0, len(manifests))
	for _, m := range manifests {
		layer, err := NewManifestLayer(m)
		if err != nil {
			return nil, err
		}
		manifestConfigs = append(manifestConfigs, *layer)
	}

	m := Manifest{
		SchemaVersion: 2,
		MediaType:     ManifestKindList,
		Manifests:     manifestConfigs,
		filepath:      p,
		fi:            nil,
		digest:        "",
	}

	return &m, json.NewEncoder(f).Encode(m)
}

func Manifests(continueOnError bool) (map[model.Name]*Manifest, error) {
	manifests, err := GetManifestPath()
	if err != nil {
		return nil, err
	}

	// TODO(mxyng): use something less brittle
	matches, err := filepath.Glob(filepath.Join(manifests, "*", "*", "*", "*"))
	if err != nil {
		return nil, err
	}

	ms := make(map[model.Name]*Manifest)
	for _, match := range matches {
		fi, err := os.Stat(match)
		if err != nil {
			return nil, err
		}

		if !fi.IsDir() {
			rel, err := filepath.Rel(manifests, match)
			if err != nil {
				if !continueOnError {
					return nil, fmt.Errorf("%s %w", match, err)
				}
				slog.Warn("bad filepath", "path", match, "error", err)
				continue
			}

			n := model.ParseNameFromFilepath(rel)
			if !n.IsValid() {
				if !continueOnError {
					return nil, fmt.Errorf("%s %w", rel, err)
				}
				slog.Warn("bad manifest name", "path", rel)
				continue
			}

			m, err := ParseNamedManifest(n)
			if err != nil {
				if !continueOnError {
					return nil, fmt.Errorf("%s %w", n, err)
				}
				slog.Warn("bad manifest", "name", n, "error", err)
				continue
			}

			ms[n] = m
		}
	}

	return ms, nil
}
