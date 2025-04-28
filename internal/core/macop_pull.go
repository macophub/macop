package core

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/macophub/macop/api"
)

type PullRequest struct {
	Insecure bool   `json:"insecure,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (m *Macop) Pull(ctx context.Context, req PullRequest, ch chan any) error {
	defer close(ch)
	fn := func(r api.ProgressResponse) {
		ch <- r
	}

	regOpts := &registryOptions{
		Insecure: req.Insecure,
		Username: req.Username,
		Password: req.Password,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := PullMCP(ctx, ParseImageName(m.image).DisplayShortest(), regOpts, fn); err != nil {
		ch <- gin.H{"error": err.Error()}
	}

	return nil
}

// todo 优化，看是否拆开
