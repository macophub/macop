package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type Layer struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	From      string   `json:"from,omitempty"`
	Platform  Platform `json:"platform,omitempty"`
	status    string
}

// Platform is a description/requirement of the cpu architecture and operating system for an image.
type Platform struct {
	Architecture string   `json:"architecture"`          // E.g. amd64, ppc64le
	OS           string   `json:"os"`                    // E.g. linux
	OSVersion    string   `json:"os.version,omitempty"`  // E.g. 10.0.10586
	OSFeatures   []string `json:"os.features,omitempty"` // Required OS features, e.g. win32k
	Variant      string   `json:"variant,omitempty"`     // Of cpu, e.g. "v6" for arm.
	Features     []string `json:"features,omitempty"`    // Required cpu features, e.g. "sse4" or "aes".
}

func NewLayer(r io.Reader, mediatype string) (Layer, error) {
	blobs, err := GetBlobsPath("")
	if err != nil {
		return Layer{}, err
	}

	temp, err := os.CreateTemp(blobs, "sha256-")
	if err != nil {
		return Layer{}, err
	}
	defer temp.Close()
	defer os.Remove(temp.Name())

	sha256sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(temp, sha256sum), r)
	if err != nil {
		return Layer{}, err
	}

	if err := temp.Close(); err != nil {
		return Layer{}, err
	}

	digest := fmt.Sprintf("sha256:%x", sha256sum.Sum(nil))
	blob, err := GetBlobsPath(digest)
	if err != nil {
		return Layer{}, err
	}

	status := "using existing layer"
	if _, err := os.Stat(blob); err != nil {
		status = "creating new layer"
		if err := os.Rename(temp.Name(), blob); err != nil {
			return Layer{}, err
		}
		if err := os.Chmod(blob, 0o644); err != nil {
			return Layer{}, err
		}
	}

	return Layer{
		MediaType: mediatype,
		Digest:    digest,
		Size:      n,
		status:    fmt.Sprintf("%s %s", status, digest),
	}, nil
}

func NewConfigLayer(layers []Layer, config ConfigV2) (*Layer, error) {
	digests := make([]string, len(layers))
	for i, layer := range layers {
		digests[i] = layer.Digest
	}
	config.RootFS.DiffIDs = digests

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(config); err != nil {
		return nil, err
	}
	layer, err := NewLayer(&b, "application/vnd.docker.container.image.v1+json")
	if err != nil {
		return nil, err
	}
	layer.Platform.OS = config.OS
	layer.Platform.Architecture = config.Architecture
	return &layer, nil
}

func NewManifestLayer(manifest *Manifest) (*Layer, error) {
	bs, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	layer, err := NewLayer(bytes.NewReader(bs), string(ManifestKindItem))
	if err != nil {
		return nil, err
	}
	layer.Platform = manifest.Config.Platform
	return &layer, nil
}

func NewManifestFromLayer(layer Layer) (*Manifest, error) {
	if layer.Digest == "" {
		return nil, errors.New("creating new manifest from layer with empty digest")
	}

	blob, err := GetBlobsPath(layer.Digest)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(blob)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var manifest Manifest
	if err := json.NewDecoder(f).Decode(&manifest); err != nil {
		return nil, err
	}

	manifest.digest = layer.Digest
	manifest.fi, err = f.Stat()
	manifest.filepath = blob

	return &manifest, nil
}

func NewLayerFromLayer(digest, mediatype, from string) (Layer, error) {
	if digest == "" {
		return Layer{}, errors.New("creating new layer from layer with empty digest")
	}

	blob, err := GetBlobsPath(digest)
	if err != nil {
		return Layer{}, err
	}

	fi, err := os.Stat(blob)
	if err != nil {
		return Layer{}, err
	}

	return Layer{
		MediaType: mediatype,
		Digest:    digest,
		Size:      fi.Size(),
		From:      from,
		status:    fmt.Sprintf("using existing layer %s", digest),
	}, nil
}

func (l *Layer) Open() (io.ReadSeekCloser, error) {
	if l.Digest == "" {
		return nil, errors.New("opening layer with empty digest")
	}

	blob, err := GetBlobsPath(l.Digest)
	if err != nil {
		return nil, err
	}

	return os.Open(blob)
}

func (l *Layer) Remove() error {
	if l.Digest == "" {
		return nil
	}

	// Ignore corrupt manifests to avoid blocking deletion of layers that are freshly orphaned
	ms, err := Manifests(true)
	if err != nil {
		return err
	}

	for _, m := range ms {
		for _, layer := range append(m.Layers, m.Config) {
			if layer.Digest == l.Digest {
				// something is using this layer
				return nil
			}
		}
	}

	blob, err := GetBlobsPath(l.Digest)
	if err != nil {
		return err
	}

	return os.Remove(blob)
}
