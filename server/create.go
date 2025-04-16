package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macophub/macop/api"
	"github.com/macophub/macop/envconfig"
	"github.com/macophub/macop/template"
	"github.com/macophub/macop/types/errtypes"
	"github.com/macophub/macop/types/model"
)

var (
	errNoFilesProvided         = errors.New("no files provided to convert")
	errOnlyOneAdapterSupported = errors.New("only one adapter is currently supported")
	errOnlyGGUFSupported       = errors.New("supplied file was not in GGUF format")
	errUnknownType             = errors.New("unknown type")
	errNeitherFromOrFiles      = errors.New("neither 'from' or 'files' was specified")
	errFilePath                = errors.New("file path must be relative")
)

func (s *Server) CreateHandler(c *gin.Context) {
	var r api.CreateRequestV2
	if err := c.ShouldBindJSON(&r); errors.Is(err, io.EOF) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing request body"})
		return
	} else if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !fs.ValidPath(r.BinFilePath) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": errFilePath.Error()})
		return
	}
	name := model.ParseName(r.Name)
	if !name.IsValid() {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": errtypes.InvalidModelNameErrMsg})
		return
	}

	name, err := getExistingName(name)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ch := make(chan any)
	go s.createHandler(c, r, name, ch)

	if r.Stream != nil && !*r.Stream {
		waitForStream(c, ch)
		return
	}

	streamResponse(c, ch)
}

func (s *Server) createHandler(_ context.Context, r api.CreateRequestV2, name model.Name, ch chan any) {
	defer close(ch)
	fn := func(resp api.ProgressResponse) {
		ch <- resp
	}

	oldManifest, _ := ParseNamedManifest(name)

	layers, err := convertModelFromFilesV2(r.BinFilePath, fn)
	if err != nil {
		for _, badReq := range []error{errNoFilesProvided, errOnlyOneAdapterSupported, errOnlyGGUFSupported, errUnknownType, errFilePath} {
			if errors.Is(err, badReq) {
				ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
				return
			}
		}
		ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
		return
	}

	if _, err := createMcpServer(api.ELFMeta{
		Os:       r.Os,
		Arch:     r.Arch,
		FilePath: r.BinFilePath,
	}, name, layers, fn); err != nil {
		if errors.Is(err, errBadTemplate) {
			ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
			return
		}
		ch <- gin.H{"error": err.Error()}
		return
	}

	if !envconfig.NoPrune() && oldManifest != nil {
		if err := oldManifest.RemoveLayers(); err != nil {
			ch <- gin.H{"error": err.Error()}
		}
	}

	ch <- api.ProgressResponse{Status: "success"}
}

func (s *Server) createHandlerV3(_ context.Context, r api.CreateRequestV3, name model.Name, ch chan any) {
	defer close(ch)
	fn := func(resp api.ProgressResponse) {
		ch <- resp
	}

	oldManifest, _ := ParseNamedManifest(name)
	manifests := make([]*Manifest, 0, len(r.ELFMetas))
	for _, meta := range r.ELFMetas {
		layers, err := convertModelFromFilesV2(meta.FilePath, fn)
		if err != nil {
			for _, badReq := range []error{errNoFilesProvided, errOnlyOneAdapterSupported, errOnlyGGUFSupported, errUnknownType, errFilePath} {
				if errors.Is(err, badReq) {
					ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
					return
				}
			}
			ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
			return
		}

		m, err := createMcpServer(api.ELFMeta{
			Os:       meta.Os,
			Arch:     meta.Arch,
			FilePath: meta.FilePath,
		}, name, layers, fn)
		if err != nil {
			if errors.Is(err, errBadTemplate) {
				ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
				return
			}
			ch <- gin.H{"error": err.Error()}
			return
		}

		manifests = append(manifests, m)
	}

	_, err := WriteManifestList(name, manifests)
	if err != nil {
		if errors.Is(err, errBadTemplate) {
			ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
			return
		}
		ch <- gin.H{"error": err.Error()}
		return
	}

	if !envconfig.NoPrune() && oldManifest != nil {
		if err := oldManifest.RemoveLayers(); err != nil {
			ch <- gin.H{"error": err.Error()}
		}
	}

	ch <- api.ProgressResponse{Status: "success"}
}

func convertModelFromFilesV2(binFilepath string, _ func(resp api.ProgressResponse)) ([]Layer, error) {
	fr, err := os.Open(binFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w, filepath=%s", err, binFilepath)
	}
	defer fr.Close()
	stat, err := fr.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w, filepath=%s", err, binFilepath)
	}
	digest, err := calculateSHA256(fr)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate SHA256: %w, filepath=%s", err, binFilepath)
	}
	blobPath, err := GetBlobsPath(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to get blobs path: %w, filepath=%s", err, binFilepath)
	}
	err = copyFile(binFilepath, blobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file: %w, src_filepath=%s, dst_filepath=%s", err, binFilepath, blobPath)
	}
	return []Layer{
		{
			MediaType: "application/vnd.macop.bin",
			Digest:    digest,
			Size:      stat.Size(),
			From:      "",
			status:    "",
		},
	}, nil
}

func createMcpServer(r api.ELFMeta, name model.Name, layers []Layer, fn func(resp api.ProgressResponse)) (m *Manifest, err error) {
	config := ConfigV2{
		OS:           r.Os,
		Architecture: r.Arch,
		RootFS: RootFS{
			Type: "layers",
		},
	}

	configLayer, err := NewConfigLayer(layers, config)
	if err != nil {
		return nil, err
	}

	for _, layer := range layers {
		if layer.status != "" {
			fn(api.ProgressResponse{Status: layer.status})
		}
	}

	fn(api.ProgressResponse{Status: "writing manifest"})
	m, err = WriteManifest(name, *configLayer, layers)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func removeLayer(layers []Layer, mediatype string) []Layer {
	return slices.DeleteFunc(layers, func(layer Layer) bool {
		if layer.MediaType != mediatype {
			return false
		}

		if err := layer.Remove(); err != nil {
			slog.Warn("couldn't remove blob", "digest", layer.Digest, "error", err)
			return true
		}

		return true
	})
}

func setTemplate(layers []Layer, t string) ([]Layer, error) {
	layers = removeLayer(layers, "application/vnd.ollama.image.template")
	if _, err := template.Parse(t); err != nil {
		return nil, fmt.Errorf("%w: %s", errBadTemplate, err)
	}
	if _, err := template.Parse(t); err != nil {
		return nil, fmt.Errorf("%w: %s", errBadTemplate, err)
	}

	blob := strings.NewReader(t)
	layer, err := NewLayer(blob, "application/vnd.ollama.image.template")
	if err != nil {
		return nil, err
	}

	layers = append(layers, layer)
	return layers, nil
}

func setSystem(layers []Layer, s string) ([]Layer, error) {
	layers = removeLayer(layers, "application/vnd.ollama.image.system")
	if s != "" {
		blob := strings.NewReader(s)
		layer, err := NewLayer(blob, "application/vnd.ollama.image.system")
		if err != nil {
			return nil, err
		}
		layers = append(layers, layer)
	}
	return layers, nil
}

func setLicense(layers []Layer, l string) ([]Layer, error) {
	blob := strings.NewReader(l)
	layer, err := NewLayer(blob, "application/vnd.ollama.image.license")
	if err != nil {
		return nil, err
	}
	layers = append(layers, layer)
	return layers, nil
}

func setParameters(layers []Layer, p map[string]any) ([]Layer, error) {
	if p == nil {
		p = make(map[string]any)
	}
	for _, layer := range layers {
		if layer.MediaType != "application/vnd.ollama.image.params" {
			continue
		}

		digestPath, err := GetBlobsPath(layer.Digest)
		if err != nil {
			return nil, err
		}

		fn, err := os.Open(digestPath)
		if err != nil {
			return nil, err
		}
		defer fn.Close()

		var existing map[string]any
		if err := json.NewDecoder(fn).Decode(&existing); err != nil {
			return nil, err
		}

		for k, v := range existing {
			if _, exists := p[k]; exists {
				continue
			}
			p[k] = v
		}
	}

	if len(p) == 0 {
		return layers, nil
	}

	layers = removeLayer(layers, "application/vnd.ollama.image.params")

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(p); err != nil {
		return nil, err
	}
	layer, err := NewLayer(&b, "application/vnd.ollama.image.params")
	if err != nil {
		return nil, err
	}
	layers = append(layers, layer)
	return layers, nil
}

func setMessages(layers []Layer, m []api.Message) ([]Layer, error) {
	// this leaves the old messages intact if no new messages were specified
	// which may not be the correct behaviour
	if len(m) == 0 {
		return layers, nil
	}

	fmt.Printf("removing old messages\n")
	layers = removeLayer(layers, "application/vnd.ollama.image.messages")
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(m); err != nil {
		return nil, err
	}
	layer, err := NewLayer(&b, "application/vnd.ollama.image.messages")
	if err != nil {
		return nil, err
	}
	layers = append(layers, layer)
	return layers, nil
}

func createLink(src, dst string) error {
	// make any subdirs for dst
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	_ = os.Remove(dst)
	if err := os.Symlink(src, dst); err != nil {
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// 计算SHA256哈希
func calculateSHA256(reader io.Reader) (string, error) {
	hash := sha256.New()
	_, err := io.Copy(hash, reader)
	if err != nil {
		return "", fmt.Errorf("failed to copy data: %w", err)
	}
	bs := hash.Sum(nil)
	return "sha256:" + hex.EncodeToString(bs[:]), nil
}
