package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macophub/macop/api"
)

type PushRequest struct {
	Insecure bool   `json:"insecure,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (m *Macop) Push(ctx context.Context, req PushRequest, ch chan any) error {
	defer close(ch)

	fn := func(r api.ProgressResponse) {
		ch <- r
	}

	regOpts := &registryOptions{
		Insecure:      req.Insecure,
		Username:      req.Username,
		Password:      req.Password,
		CheckRedirect: nil,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	name, err := getExistingName(ParseImageName(m.image))
	if err != nil {
		ch <- gin.H{"error": err.Error()}
		return fmt.Errorf("error")
	}

	if err := PushMCP(ctx, name.DisplayShortest(), regOpts, fn); err != nil {
		ch <- gin.H{"error": err.Error()}
	}
	return nil
}

// getExistingName searches the models directory for the longest prefix match of
// the input name and returns the input name with all existing parts replaced
// with each part found. If no parts are found, the input name is returned as
// is.
func getExistingName(n Name) (Name, error) {
	var zero Name
	existing, err := Manifests(true)
	if err != nil {
		return zero, err
	}
	var set Name // tracks parts already canonicalized
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
