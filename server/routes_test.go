package server

import (
	"context"
	"net"
	"testing"

	"github.com/macophub/macop/api"
	"github.com/macophub/macop/types/model"
)

func TestServer_pushHandler(t *testing.T) {
	type fields struct {
		addr net.Addr
	}
	type args struct {
		ctx context.Context
		req api.PushRequest
		ch  chan any
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "1",
			fields: fields{
				addr: nil,
			},
			args: args{
				ctx: context.Background(),
				req: api.PushRequest{
					Model:    "ccheers/cctest:v1.7",
					Insecure: false,
					Username: "ccheers",
					Password: "xxxx",
					Stream:   nil,
				},
				ch: make(chan any, 1024),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				addr: tt.fields.addr,
			}
			go func() {
				for item := range tt.args.ch {
					t.Logf("item: %v", item)
				}
			}()
			s.pushHandler(tt.args.ctx, tt.args.req, tt.args.ch)
			for item := range tt.args.ch {
				t.Logf("item: %v", item)
			}
		})
	}
}

func TestServer_pullHandler(t *testing.T) {
	type fields struct {
		addr net.Addr
	}
	type args struct {
		ctx  context.Context
		req  api.PullRequest
		name model.Name
		ch   chan any
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "1",
			fields: fields{
				addr: nil,
			},
			args: args{
				ctx: context.Background(),
				req: api.PullRequest{
					Insecure: false,
					Username: "ccheers",
					Password: "xxxx",
					Stream:   nil,
				},
				name: model.ParseImageName("ccheers/cctest:v1.7"),
				ch:   make(chan any, 1024),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				addr: tt.fields.addr,
			}
			go func() {
				for item := range tt.args.ch {
					t.Logf("item: %v", item)
				}
			}()
			s.pullHandler(tt.args.ctx, tt.args.req, tt.args.name, tt.args.ch)
			for item := range tt.args.ch {
				t.Logf("item: %v", item)
			}
		})
	}
}
