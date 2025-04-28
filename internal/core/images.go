package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/macophub/macop/api"
	"github.com/macophub/macop/envconfig"
	"gopkg.in/yaml.v3"
)

var (
	errCapabilities         = errors.New("does not support")
	errCapabilityCompletion = errors.New("completion")
	errCapabilityTools      = errors.New("tools")
	errCapabilityInsert     = errors.New("insert")
	errCapabilityVision     = errors.New("vision")
	errCapabilityEmbedding  = errors.New("embedding")
	errInsecureProtocol     = errors.New("insecure protocol http")
)

type registryOptions struct {
	Insecure bool
	Username string
	Password string
	Token    string

	CheckRedirect func(req *http.Request, via []*http.Request) error
}

type ConfigV2 struct {
	RawConfig []byte `json:"rawConfig"`
	// macop config
	//MacopConfig MacopConfig `json:"macop_config"`

	// required by spec
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	RootFS       RootFS `json:"rootfs"`
}

type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

func GetManifest(mp MCPPath) (*Manifest, string, error) {
	fp, err := mp.GetManifestPath()
	if err != nil {
		return nil, "", err
	}

	f, err := os.Open(fp)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	sha256sum := sha256.New()

	var manifest Manifest
	if err := json.NewDecoder(io.TeeReader(f, sha256sum)).Decode(&manifest); err != nil {
		return nil, "", err
	}

	return &manifest, hex.EncodeToString(sha256sum.Sum(nil)), nil
}

func CopyModel(src, dst Name) error {
	if !dst.IsFullyQualified() {
		return Unqualified(dst)
	}
	if !src.IsFullyQualified() {
		return Unqualified(src)
	}

	if src.Filepath() == dst.Filepath() {
		return nil
	}

	manifests, err := GetManifestPath()
	if err != nil {
		return err
	}

	dstpath := filepath.Join(manifests, dst.Filepath())
	if err := os.MkdirAll(filepath.Dir(dstpath), 0o755); err != nil {
		return err
	}

	srcpath := filepath.Join(manifests, src.Filepath())
	srcfile, err := os.Open(srcpath)
	if err != nil {
		return err
	}
	defer srcfile.Close()

	dstfile, err := os.Create(dstpath)
	if err != nil {
		return err
	}
	defer dstfile.Close()

	_, err = io.Copy(dstfile, srcfile)
	return err
}

func deleteUnusedLayers(deleteMap map[string]struct{}) error {
	// Ignore corrupt manifests to avoid blocking deletion of layers that are freshly orphaned
	manifests, err := Manifests(true)
	if err != nil {
		return err
	}

	for _, manifest := range manifests {
		for _, layer := range manifest.Layers {
			delete(deleteMap, layer.Digest)
		}

		delete(deleteMap, manifest.Config.Digest)
	}

	// only delete the files which are still in the deleteMap
	for k := range deleteMap {
		fp, err := GetBlobsPath(k)
		if err != nil {
			slog.Info(fmt.Sprintf("couldn't get file path for '%s': %v", k, err))
			continue
		}
		if err := os.Remove(fp); err != nil {
			slog.Info(fmt.Sprintf("couldn't remove file '%s': %v", fp, err))
			continue
		}
	}

	return nil
}

func PruneLayers() error {
	deleteMap := make(map[string]struct{})
	p, err := GetBlobsPath("")
	if err != nil {
		return err
	}

	blobs, err := os.ReadDir(p)
	if err != nil {
		slog.Info(fmt.Sprintf("couldn't read dir '%s': %v", p, err))
		return err
	}

	for _, blob := range blobs {
		name := blob.Name()
		name = strings.ReplaceAll(name, "-", ":")

		_, err := GetBlobsPath(name)
		if err != nil {
			if errors.Is(err, ErrInvalidDigestFormat) {
				// remove invalid blobs (e.g. partial downloads)
				if err := os.Remove(filepath.Join(p, blob.Name())); err != nil {
					slog.Error("couldn't remove blob", "blob", blob.Name(), "error", err)
				}
			}

			continue
		}

		deleteMap[name] = struct{}{}
	}

	slog.Info(fmt.Sprintf("total blobs: %d", len(deleteMap)))

	if err := deleteUnusedLayers(deleteMap); err != nil {
		slog.Error(fmt.Sprintf("couldn't remove unused layers: %v", err))
		return nil
	}

	slog.Info(fmt.Sprintf("total unused blobs removed: %d", len(deleteMap)))

	return nil
}

func PruneDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			if err := PruneDirectory(filepath.Join(path, entry.Name())); err != nil {
				return err
			}
		}

		entries, err = os.ReadDir(path)
		if err != nil {
			return err
		}

		if len(entries) > 0 {
			return nil
		}

		return os.Remove(path)
	}

	return nil
}

func PushMCP(ctx context.Context, name string, regOpts *registryOptions, fn func(api.ProgressResponse)) error {
	mp := ParseMCPPath(name)
	fn(api.ProgressResponse{Status: "retrieving manifest"})

	if mp.ProtocolScheme == "http" && !regOpts.Insecure {
		return errInsecureProtocol
	}

	manifest, _, err := GetManifest(mp)
	if err != nil {
		fn(api.ProgressResponse{Status: "couldn't retrieve manifest"})
		return err
	}

	if mp.ProtocolScheme == "http" && !regOpts.Insecure {
		return errInsecureProtocol
	}

	switch manifest.MediaType {
	case ManifestKindItem:
		return pushMCP4Item(ctx, mp, manifest, regOpts, fn)
	case ManifestKindList:
		return pushMCP4List(ctx, mp, manifest, regOpts, fn)

	}

	return fmt.Errorf("unsupported manifest media type: %s", manifest.MediaType)
}

func pushMCP4Item(ctx context.Context, mp MCPPath, manifest *Manifest, regOpts *registryOptions, fn func(api.ProgressResponse)) error {
	if manifest.MediaType != ManifestKindItem {
		return fmt.Errorf("invalid manifest media type: %s", manifest.MediaType)
	}

	var layers []Layer
	layers = append(layers, manifest.Layers...)
	if manifest.Config.Digest != "" {
		layers = append(layers, manifest.Config)
	}

	for _, layer := range layers {
		if err := uploadBlob(ctx, mp, layer, regOpts, fn); err != nil {
			slog.Info(fmt.Sprintf("error uploading blob: %v", err))
			return err
		}
	}

	fn(api.ProgressResponse{Status: "pushing manifest"})
	requestURL := mp.BaseURL()
	requestURL = requestURL.JoinPath("v2", mp.GetNamespaceRepository(), "manifests", mp.Tag)

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	headers := make(http.Header)
	headers.Set("Content-Type", string(ManifestKindItem))
	resp, err := makeRequestWithRetry(ctx, http.MethodPut, requestURL, headers, bytes.NewReader(manifestJSON), regOpts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	fn(api.ProgressResponse{Status: "success"})

	return nil
}

func pushMCP4List(ctx context.Context, mp MCPPath, manifest *Manifest, regOpts *registryOptions, fn func(api.ProgressResponse)) error {
	if manifest.MediaType != ManifestKindList {
		return fmt.Errorf("invalid manifest media type: %s", manifest.MediaType)
	}

	var layers []Layer
	subManifests := make([]*Manifest, 0, len(manifest.Manifests))

	for _, layer := range manifest.Manifests {
		manifest, err := NewManifestFromLayer(layer)
		if err != nil {
			return fmt.Errorf("invalid manifest layer: %s", err)
		}
		subManifests = append(subManifests, manifest)
		if manifest.Config.Digest != "" {
			layers = append(layers, manifest.Config)
		}
		layers = append(layers, manifest.Layers...)
	}

	for _, layer := range layers {
		if err := uploadBlob(ctx, mp, layer, regOpts, fn); err != nil {
			slog.Error(fmt.Sprintf("error uploading blob: %v", err))
			return err
		}
	}
	for _, subManifest := range subManifests {
		err := pushSubMCPManifest(ctx, mp, subManifest, regOpts, fn)
		if err != nil {
			slog.Error(fmt.Sprintf("error uploading sub manifest: %v", err))
			return err
		}
	}

	fn(api.ProgressResponse{Status: "pushing manifest"})
	requestURL := mp.BaseURL()
	requestURL = requestURL.JoinPath("v2", mp.GetNamespaceRepository(), "manifests", mp.Tag)

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	headers := make(http.Header)
	headers.Set("Content-Type", string(ManifestKindList))
	resp, err := makeRequestWithRetry(ctx, http.MethodPut, requestURL, headers, bytes.NewReader(manifestJSON), regOpts)
	if err != nil {
		slog.Error("[pushMCP4List][pushManifest][makeRequestWithRetry]", "err", err.Error())
		return err
	}
	defer resp.Body.Close()

	bs, _ := io.ReadAll(resp.Body)
	slog.Info("push manifest resp", "boby", string(bs))

	fn(api.ProgressResponse{Status: "success"})

	return nil
}

func PullMCP(ctx context.Context, name string, regOpts *registryOptions, fn func(api.ProgressResponse)) error {
	mp := ParseMCPPath(name)

	// build deleteMap to prune unused layers
	deleteMap := make(map[string]struct{})
	manifest, _, err := GetManifest(mp)
	if errors.Is(err, os.ErrNotExist) {
		// noop
	} else if err != nil {
		slog.Warn("pulling model with bad existing manifest", "name", name, "error", err)
	} else {
		for _, l := range manifest.Layers {
			deleteMap[l.Digest] = struct{}{}
		}
		if manifest.Config.Digest != "" {
			deleteMap[manifest.Config.Digest] = struct{}{}
		}
	}

	if mp.ProtocolScheme == "http" && !regOpts.Insecure {
		return errInsecureProtocol
	}

	fn(api.ProgressResponse{Status: "pulling manifest"})

	manifest, err = pullModelManifest(ctx, mp, regOpts)
	if err != nil {
		return fmt.Errorf("pull model manifest: %s", err)
	}
	var layers []Layer
	switch manifest.MediaType {
	case ManifestKindItem:
		layers, err = pullMCP4Item(ctx, mp, manifest, regOpts, deleteMap, fn)
	case ManifestKindList:
		layers, err = pullMCP4List(ctx, mp, manifest, regOpts, deleteMap, fn)
	default:
		return fmt.Errorf("unsupported manifest media type: %s", manifest.MediaType)
	}
	// todo 优化 layer 写死的
	configDigest := layers[1].Digest
	configFp, err := GetBlobsPath(configDigest)
	if err != nil {
		return fmt.Errorf("couldn't get file path for '%s': %v", configDigest, err)
	}
	readFile, err := os.ReadFile(configFp)
	if err != nil {
		return fmt.Errorf("couldn't read file path for '%s': %v", configDigest, err)
	}

	var configFpData ConfigV2
	if err := json.Unmarshal(readFile, &configFpData); err != nil {
		return fmt.Errorf("json unmarshal error: %w", err)
	}

	var macopYaml MacopConfig
	err = yaml.Unmarshal(configFpData.RawConfig, &macopYaml)
	if err != nil {
		return fmt.Errorf("yaml unmarshal error: %w", err)
	}

	entrypointDigest := layers[0].Digest
	entrypointFp, err := GetBlobsPath(entrypointDigest)
	if err != nil {
		return fmt.Errorf("couldn't get file path for '%s': %v", entrypointDigest, err)
	}

	yamlMp := ParseMCPPath(macopYaml.Metadata.Image)
	runPath, err := yamlMp.GetRunPath()
	if err != nil {
		return fmt.Errorf("couldn't get run path for '%s': %v", entrypointDigest, err)
	}
	// 根据 macopYaml.spec.entrypoint，将entrypointFp copy 到指定runPath，并将名字改为macopYaml.spec.entrypoint ，给 chmod +x 权限
	if err := os.MkdirAll(runPath, 0o755); err != nil {
		return fmt.Errorf("couldn't create directory '%s': %v", runPath, err)
	}
	if err := os.Rename(entrypointFp, filepath.Join(runPath, macopYaml.Spec.Entrypoint)); err != nil {
		return fmt.Errorf("couldn't rename file '%s' to '%s': %v", entrypointFp, filepath.Join(runPath, macopYaml.Spec.Entrypoint), err)
	}
	if err := os.Chmod(filepath.Join(runPath, macopYaml.Spec.Entrypoint), 0o755); err != nil {
		return fmt.Errorf("couldn't change file permission '%s': %v", entrypointFp, err)
	}
	slog.Info("Your exec file is " + filepath.Join(runPath, macopYaml.Spec.Entrypoint))

	if !envconfig.NoPrune() && len(deleteMap) > 0 {
		fn(api.ProgressResponse{Status: "removing unused layers"})
		if err := deleteUnusedLayers(deleteMap); err != nil {
			fn(api.ProgressResponse{Status: fmt.Sprintf("couldn't remove unused layers: %v", err)})
		}
	}
	return nil
}

func pullMCP4Item(ctx context.Context, mp MCPPath, manifest *Manifest, regOpts *registryOptions, deleteMap map[string]struct{}, fn func(api.ProgressResponse)) (layers []Layer, err error) {
	if manifest.MediaType != ManifestKindItem {
		return nil, fmt.Errorf("invalid manifest media type: %s", manifest.MediaType)
	}
	layers = append(layers, manifest.Layers...)
	if manifest.Config.Digest != "" {
		layers = append(layers, manifest.Config)
	}

	skipVerify := make(map[string]bool)
	for _, layer := range layers {
		cacheHit, err := downloadBlob(ctx, downloadOpts{
			mp:      mp,
			digest:  layer.Digest,
			regOpts: regOpts,
			fn:      fn,
		})
		if err != nil {
			return nil, err
		}
		skipVerify[layer.Digest] = cacheHit
		delete(deleteMap, layer.Digest)
	}
	delete(deleteMap, manifest.Config.Digest)

	fn(api.ProgressResponse{Status: "verifying sha256 digest"})
	for _, layer := range layers {
		if skipVerify[layer.Digest] {
			continue
		}
		if err := verifyBlob(layer.Digest); err != nil {
			if errors.Is(err, errDigestMismatch) {
				// something went wrong, delete the blob
				fp, err := GetBlobsPath(layer.Digest)
				if err != nil {
					return nil, err
				}
				if err := os.Remove(fp); err != nil {
					// log this, but return the original error
					slog.Info(fmt.Sprintf("couldn't remove file with digest mismatch '%s': %v", fp, err))
				}
			}
			return nil, err
		}
	}

	fn(api.ProgressResponse{Status: "writing manifest"})

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	fp, err := mp.GetManifestPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
		return nil, err
	}

	err = os.WriteFile(fp, manifestJSON, 0o644)
	if err != nil {
		slog.Error(fmt.Sprintf("couldn't write to %s", fp))
		return nil, err
	}

	fn(api.ProgressResponse{Status: "success"})

	return
}

func pullMCP4List(ctx context.Context, mp MCPPath, manifest *Manifest, regOpts *registryOptions, deleteMap map[string]struct{}, fn func(api.ProgressResponse)) (layers []Layer, err error) {
	if manifest.MediaType != ManifestKindList {
		return nil, fmt.Errorf("invalid manifest media type: %s", manifest.MediaType)
	}
	for _, layer := range manifest.Manifests {
		if layer.Platform.OS != runtime.GOOS ||
			layer.Platform.Architecture != runtime.GOARCH {
			slog.Warn("skipping layer for different platform", "layer", layer)
			continue
		}
		var pullManifest *Manifest
		pullManifest, err = pullModelManifest(ctx, MCPPath{
			ProtocolScheme: mp.ProtocolScheme,
			Registry:       mp.Registry,
			Namespace:      mp.Namespace,
			Repository:     mp.Repository,
			Tag:            layer.Digest,
		}, regOpts)
		if err != nil {
			return nil, fmt.Errorf("pull mcp pullManifest: err=%s", err)
		}
		// Download
		layers, err = pullMCP4Item(ctx, mp, pullManifest, regOpts, deleteMap, fn)
		if err != nil {
			return nil, fmt.Errorf("pull mcp pullManifest: err=%s", err)
		}
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	fp, err := mp.GetManifestPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
		return nil, err
	}
	err = os.WriteFile(fp, manifestJSON, 0o644)
	if err != nil {
		slog.Error(fmt.Sprintf("couldn't write to %s", fp))
		return nil, err
	}

	fn(api.ProgressResponse{Status: "success"})

	return
}

func pullModelManifest(ctx context.Context, mp MCPPath, regOpts *registryOptions) (*Manifest, error) {
	requestURL := mp.BaseURL().JoinPath("v2", mp.GetNamespaceRepository(), "manifests", mp.Tag)

	headers := make(http.Header)
	headers.Add("Accept", string(ManifestKindItem))
	headers.Add("Accept", string(ManifestKindList))
	resp, err := makeRequestWithRetry(ctx, http.MethodGet, requestURL, headers, nil, regOpts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}

	return &m, err
}

// GetSHA256Digest returns the SHA256 hash of a given buffer and returns it, and the size of buffer
func GetSHA256Digest(r io.Reader) (string, int64) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), n
}

var errUnauthorized = errors.New("unauthorized: access denied")

func makeRequestWithRetry(ctx context.Context, method string, requestURL *url.URL, headers http.Header, body io.ReadSeeker, regOpts *registryOptions) (*http.Response, error) {
	for range 2 {
		resp, err := makeRequest(ctx, method, requestURL, headers, body, regOpts)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				slog.Info(fmt.Sprintf("request failed: %v", err))
			}

			return nil, err
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			resp.Body.Close()

			// Handle authentication error with one retry
			challenge := parseRegistryChallenge(resp.Header.Get("www-authenticate"))
			token, err := getAuthorizationToken(ctx, challenge, regOpts)
			if err != nil {
				return nil, err
			}
			regOpts.Token = token
			if body != nil {
				_, err = body.Seek(0, io.SeekStart)
				if err != nil {
					return nil, err
				}
			}
		case resp.StatusCode == http.StatusNotFound:
			resp.Body.Close()
			return nil, os.ErrNotExist
		case resp.StatusCode >= http.StatusBadRequest:
			defer resp.Body.Close()
			responseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("%d: %s", resp.StatusCode, err)
			}
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, responseBody)
		default:
			return resp, nil
		}
	}

	return nil, errUnauthorized
}

// testMakeRequestDialContext specifies the dial function for the http client in
// makeRequest. It can be used to resolve hosts in model names to local
// addresses for testing. For example, the model name ("example.com/my/model")
// can be directed to push/pull from "127.0.0.1:1234".
//
// This is not safe to set across goroutines. It should be set in
// the main test goroutine, and not by tests marked to run in parallel with
// t.Parallel().
//
// It should be cleared after use, otherwise it will affect other tests.
//
// Ideally we would have some set this up the stack, but the code is not
// structured in a way that makes this easy, so this will have to do for now.
var testMakeRequestDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func makeRequest(ctx context.Context, method string, requestURL *url.URL, headers http.Header, body io.Reader, regOpts *registryOptions) (*http.Response, error) {
	if requestURL.Scheme != "http" && regOpts != nil && regOpts.Insecure {
		requestURL.Scheme = "http"
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return nil, err
	}

	if headers != nil {
		req.Header = headers
	}

	if regOpts != nil {
		if regOpts.Token != "" {
			req.Header.Set("Authorization", "Bearer "+regOpts.Token)
		} else if regOpts.Username != "" && regOpts.Password != "" {
			req.SetBasicAuth(regOpts.Username, regOpts.Password)
		}
	}

	if s := req.Header.Get("Content-Length"); s != "" {
		contentLength, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}

		req.ContentLength = contentLength
	}

	c := &http.Client{
		CheckRedirect: regOpts.CheckRedirect,
	}
	if testMakeRequestDialContext != nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = testMakeRequestDialContext
		c.Transport = tr
	}
	return c.Do(req)
}

func getValue(header, key string) string {
	startIdx := strings.Index(header, key+"=")
	if startIdx == -1 {
		return ""
	}

	// Move the index to the starting quote after the key.
	startIdx += len(key) + 2
	endIdx := startIdx

	for endIdx < len(header) {
		if header[endIdx] == '"' {
			if endIdx+1 < len(header) && header[endIdx+1] != ',' { // If the next character isn't a comma, continue
				endIdx++
				continue
			}
			break
		}
		endIdx++
	}
	return header[startIdx:endIdx]
}

func parseRegistryChallenge(authStr string) registryChallenge {
	authStr = strings.TrimPrefix(authStr, "Bearer ")

	return registryChallenge{
		Realm:   getValue(authStr, "realm"),
		Service: getValue(authStr, "service"),
		Scope:   getValue(authStr, "scope"),
	}
}

var errDigestMismatch = errors.New("digest mismatch, file must be downloaded again")

func verifyBlob(digest string) error {
	fp, err := GetBlobsPath(digest)
	if err != nil {
		return err
	}

	f, err := os.Open(fp)
	if err != nil {
		return err
	}
	defer f.Close()

	fileDigest, _ := GetSHA256Digest(f)
	if digest != fileDigest {
		return fmt.Errorf("%w: want %s, got %s", errDigestMismatch, digest, fileDigest)
	}

	return nil
}

func pushSubMCPManifest(ctx context.Context, mp MCPPath, manifest *Manifest, opts *registryOptions, _ func(api.ProgressResponse)) error {
	requestURL := mp.BaseURL()
	requestURL = requestURL.JoinPath("v2", mp.GetNamespaceRepository(), "manifests", manifest.digest)

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		slog.Error("[pushSubMCPManifest][json.Marshal]", "err", err.Error())
		return err
	}

	headers := make(http.Header)
	headers.Set("Content-Type", string(ManifestKindItem))
	slog.Info("pushSubMCPManifest", "url", requestURL.String(), "headers", headers, "body", string(manifestJSON), "digest", fmt.Sprintf("%x", sha256.Sum256(manifestJSON)))

	resp, err := makeRequestWithRetry(ctx, http.MethodPut, requestURL, headers, bytes.NewReader(manifestJSON), opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
