package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/macophub/macop/api"
	"github.com/macophub/macop/envconfig"
)

var (
	errRequired    = errors.New("is required")
	errBadTemplate = errors.New("template error")
)

func (m *Macop) Create(ctx context.Context, ch chan any) error {
	defer close(ch)
	fn := func(resp api.ProgressResponse) {
		ch <- resp
	}
	imageName := ParseImageName(m.config.Metadata.Image)
	oldManifest, _ := ParseNamedManifest(imageName)
	//if err != nil {
	//	return fmt.Errorf("failed to parse image name: err=%w", err)
	//}
	manifests := make([]*Manifest, 0, len(m.config.Spec.Builds))
	for _, buildInfo := range m.config.Spec.Builds {
		layers, err := convertModelFromFilesV2(buildInfo.BinFilepath, fn)
		if err != nil {
			for _, badReq := range []error{errNoFilesProvided, errOnlyOneAdapterSupported, errOnlyGGUFSupported, errUnknownType, errFilePath} {
				if errors.Is(err, badReq) {
					ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
					return fmt.Errorf("err")
				}
			}
			ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
			return fmt.Errorf("err")
		}
		manifest, err := createMcpServer(m.rawContent, buildInfo, imageName, layers, fn)
		if err != nil {
			if errors.Is(err, errBadTemplate) {
				ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
				return fmt.Errorf("err")
			}
			ch <- gin.H{"error": err.Error()}
			return fmt.Errorf("err")
		}
		manifests = append(manifests, manifest)
	}

	_, err := WriteManifestList(imageName, manifests)
	if err != nil {
		if errors.Is(err, errBadTemplate) {
			ch <- gin.H{"error": err.Error(), "status": http.StatusBadRequest}
			return fmt.Errorf("err")
		}
		ch <- gin.H{"error": err.Error()}
		return fmt.Errorf("err")
	}

	if !envconfig.NoPrune() && oldManifest != nil {
		if err := oldManifest.RemoveLayers(); err != nil {
			ch <- gin.H{"error": err.Error()}
		}
	}
	return nil
}

func createMcpServer(rawConfig []byte, r MacopConfigSpecBuild, name Name, layers []Layer, fn func(resp api.ProgressResponse)) (m *Manifest, err error) {
	config := ConfigV2{
		RawConfig:    rawConfig,
		Architecture: r.Architecture,
		OS:           r.Os,
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
