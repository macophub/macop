package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/macophub/macop/api"
	"github.com/macophub/macop/envconfig"
	"github.com/macophub/macop/types/errtypes"
	"github.com/macophub/macop/types/model"
	"github.com/macophub/macop/version"
)

type Server struct {
	addr net.Addr
	//sched *Scheduler
}

func Serve(ln net.Listener) error {
	level := slog.LevelInfo
	if envconfig.Debug() {
		level = slog.LevelDebug
	}

	slog.Info("server config", "env", envconfig.Values())
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.SourceKey {
				source := attr.Value.Any().(*slog.Source)
				source.File = filepath.Base(source.File)
			}

			return attr
		},
	})

	slog.SetDefault(slog.New(handler))

	//blobsDir, err := GetBlobsPath("")
	//if err != nil {
	//	return err
	//}
	//if err := fixBlobs(blobsDir); err != nil {
	//	return err
	//}

	if !envconfig.NoPrune() {
		if _, err := Manifests(false); err != nil {
			slog.Warn("corrupt manifests detected, skipping prune operation.  Re-pull or delete to clear", "error", err)
		} else {
			// clean up unused layers and manifests
			if err := PruneLayers(); err != nil {
				return err
			}

			manifestsPath, err := GetManifestPath()
			if err != nil {
				return err
			}

			if err := PruneDirectory(manifestsPath); err != nil {
				return err
			}
		}
	}

	s := &Server{addr: ln.Addr()}

	//var rc *macop.Registry
	//var err error
	//rc, err = macop.DefaultRegistry()
	//if err != nil {
	//	return err
	//}

	h, err := s.GenerateRoutes()
	if err != nil {
		return err
	}

	http.Handle("/", h)

	//ctx, done := context.WithCancel(context.Background())
	//schedCtx, schedDone := context.WithCancel(ctx)
	//sched := InitScheduler(schedCtx)
	//s.sched = sched

	slog.Info(fmt.Sprintf("Listening on %s (version %s)", ln.Addr(), version.Version))
	srvr := &http.Server{
		// Use http.DefaultServeMux so we get net/http/pprof for
		// free.
		//
		// TODO(bmizerany): Decide if we want to make this
		// configurable so it is not exposed by default, or allow
		// users to bind it to a different port. This was a quick
		// and easy way to get pprof, but it may not be the best
		// way.
		Handler: nil,
	}

	// listen for a ctrl+c and stop any loaded llm
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	//go func() {
	//	<-signals
	//	srvr.Close()
	//	//schedDone()
	//	//sched.unloadAllRunners()
	//	//done()
	//}()

	//s.sched.Run(schedCtx)

	// At startup we retrieve GPU information so we can get log messages before loading a model
	// This will log warnings to the log in case we have problems with detected GPUs
	//gpus := discover.GetGPUInfo()
	//gpus.LogDetails()

	err = srvr.Serve(ln)
	// If server is closed from the signal handler, wait for the ctx to be done
	// otherwise error out quickly
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	//<-ctx.Done()
	return nil
}

func allowedHostsMiddleware(addr net.Addr) gin.HandlerFunc {
	return func(c *gin.Context) {
		if addr == nil {
			c.Next()
			return
		}

		if addr, err := netip.ParseAddrPort(addr.String()); err == nil && !addr.Addr().IsLoopback() {
			c.Next()
			return
		}

		host, _, err := net.SplitHostPort(c.Request.Host)
		if err != nil {
			host = c.Request.Host
		}

		if addr, err := netip.ParseAddr(host); err == nil {
			if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || isLocalIP(addr) {
				c.Next()
				return
			}
		}

		if allowedHost(host) {
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}

			c.Next()
			return
		}

		c.AbortWithStatus(http.StatusForbidden)
	}
}

func (s *Server) GenerateRoutes() (http.Handler, error) {
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowWildcard = true
	corsConfig.AllowBrowserExtensions = true
	corsConfig.AllowHeaders = []string{
		"Authorization",
		"Content-Type",
		"User-Agent",
		"Accept",
		"X-Requested-With",

		// OpenAI compatibility headers
		"x-stainless-lang",
		"x-stainless-package-version",
		"x-stainless-os",
		"x-stainless-arch",
		"x-stainless-retry-count",
		"x-stainless-runtime",
		"x-stainless-runtime-version",
		"x-stainless-async",
		"x-stainless-helper-method",
		"x-stainless-poll-helper",
		"x-stainless-custom-poll-interval",
		"x-stainless-timeout",
	}
	corsConfig.AllowOrigins = envconfig.AllowedOrigins()

	r := gin.Default()
	r.Use(
		cors.New(corsConfig),
		allowedHostsMiddleware(s.addr),
	)

	// General
	r.HEAD("/", func(c *gin.Context) { c.String(http.StatusOK, "Ollama is running") })
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "Ollama is running") })
	r.HEAD("/api/version", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"version": version.Version}) })
	r.GET("/api/version", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"version": version.Version}) })

	// Local model cache management (new implementation is at end of function)
	r.POST("/api/pull", s.PullHandler)
	//
	//if rc != nil {
	//	// wrap old with new
	//	rs := &registry.Local{
	//		Client:   rc,
	//		Logger:   slog.Default(), // TODO(bmizerany): Take a logger, do not use slog.Default()
	//		Fallback: r,
	//
	//		Prune: PruneLayers,
	//	}
	//	return rs, nil
	//}

	return r, nil
}

func (s *Server) PullHandler(c *gin.Context) {
	var req api.PullRequest
	err := c.ShouldBindJSON(&req)
	switch {
	case errors.Is(err, io.EOF):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing request body"})
		return
	case err != nil:
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	name := model.ParseName(cmp.Or(req.Model, req.Name))
	if !name.IsValid() {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": errtypes.InvalidModelNameErrMsg})
		return
	}

	name, err = getExistingName(name)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ch := make(chan any)
	go func() {
		defer close(ch)
		fn := func(r api.ProgressResponse) {
			ch <- r
		}

		regOpts := &registryOptions{
			Insecure: req.Insecure,
		}

		ctx, cancel := context.WithCancel(c.Request.Context())
		defer cancel()

		if err := PullModel(ctx, name.DisplayShortest(), regOpts, fn); err != nil {
			ch <- gin.H{"error": err.Error()}
		}
	}()

	if req.Stream != nil && !*req.Stream {
		waitForStream(c, ch)
		return
	}

	streamResponse(c, ch)
}

func isLocalIP(ip netip.Addr) bool {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, a := range addrs {
				if parsed, _, err := net.ParseCIDR(a.String()); err == nil {
					if parsed.String() == ip.String() {
						return true
					}
				}
			}
		}
	}

	return false
}

func allowedHost(host string) bool {
	host = strings.ToLower(host)

	if host == "" || host == "localhost" {
		return true
	}

	if hostname, err := os.Hostname(); err == nil && host == strings.ToLower(hostname) {
		return true
	}

	tlds := []string{
		"localhost",
		"local",
		"internal",
	}

	// check if the host is a local TLD
	for _, tld := range tlds {
		if strings.HasSuffix(host, "."+tld) {
			return true
		}
	}

	return false
}

// getExistingName searches the models directory for the longest prefix match of
// the input name and returns the input name with all existing parts replaced
// with each part found. If no parts are found, the input name is returned as
// is.
func getExistingName(n model.Name) (model.Name, error) {
	var zero model.Name
	existing, err := Manifests(true)
	if err != nil {
		return zero, err
	}
	var set model.Name // tracks parts already canonicalized
	for e := range existing {
		if set.Host == "" && strings.EqualFold(e.Host, n.Host) {
			n.Host = e.Host
		}
		if set.Namespace == "" && strings.EqualFold(e.Namespace, n.Namespace) {
			n.Namespace = e.Namespace
		}
		if set.Model == "" && strings.EqualFold(e.Model, n.Model) {
			n.Model = e.Model
		}
		if set.Tag == "" && strings.EqualFold(e.Tag, n.Tag) {
			n.Tag = e.Tag
		}
	}
	return n, nil
}

func waitForStream(c *gin.Context, ch chan interface{}) {
	c.Header("Content-Type", "application/json")
	for resp := range ch {
		switch r := resp.(type) {
		case api.ProgressResponse:
			if r.Status == "success" {
				c.JSON(http.StatusOK, r)
				return
			}
		case gin.H:
			status, ok := r["status"].(int)
			if !ok {
				status = http.StatusInternalServerError
			}
			if errorMsg, ok := r["error"].(string); ok {
				c.JSON(status, gin.H{"error": errorMsg})
				return
			} else {
				c.JSON(status, gin.H{"error": "unexpected error format in progress response"})
				return
			}
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected progress response"})
			return
		}
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected end of progress response"})
}

func streamResponse(c *gin.Context, ch chan any) {
	c.Header("Content-Type", "application/x-ndjson")
	c.Stream(func(w io.Writer) bool {
		val, ok := <-ch
		if !ok {
			return false
		}

		bts, err := json.Marshal(val)
		if err != nil {
			slog.Info(fmt.Sprintf("streamResponse: json.Marshal failed with %s", err))
			return false
		}

		// Delineate chunks with new-line delimiter
		bts = append(bts, '\n')
		if _, err := w.Write(bts); err != nil {
			slog.Info(fmt.Sprintf("streamResponse: w.Write failed with %s", err))
			return false
		}

		return true
	})
}
