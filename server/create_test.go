package server

import (
	"context"
	"net"
	"testing"

	"github.com/macophub/macop/api"
	"github.com/macophub/macop/types/model"
)

func TestServer_createHandler(t *testing.T) {
	type fields struct {
		addr net.Addr
	}
	type args struct {
		in0  context.Context
		r    api.CreateRequestV2
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
				in0: context.Background(),
				r: api.CreateRequestV2{
					Name:        "cctest",
					Stream:      nil,
					Os:          "linux",
					Arch:        "amd64",
					BinFilePath: "/Users/eric/GoProject/macop/server/auth.go",
				},
				name: model.ParseImageName("ccheers/cctest:v1.2"),
				ch:   make(chan any, 1024),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				addr: tt.fields.addr,
			}
			s.createHandler(tt.args.in0, tt.args.r, tt.args.name, tt.args.ch)
		})
	}
}

func TestServer_createHandlerV3(t *testing.T) {
	type fields struct {
		addr net.Addr
	}
	type args struct {
		in0  context.Context
		r    api.CreateRequestV3
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
				in0: context.Background(),
				r: api.CreateRequestV3{
					Name:   "cctest",
					Stream: nil,
					ELFMetas: []api.ELFMeta{
						{
							Os:       "linux",
							Arch:     "amd64",
							FilePath: "/Users/eric/GoProject/macop/server/auth.go",
						},
						{
							Os:       "linux",
							Arch:     "arm64",
							FilePath: "/Users/eric/GoProject/macop/server/auth.go",
						},
						{
							Os:       "darwin",
							Arch:     "amd64",
							FilePath: "/Users/eric/GoProject/macop/server/auth.go",
						},
						{
							Os:       "darwin",
							Arch:     "arm64",
							FilePath: "/Users/eric/GoProject/macop/server/auth.go",
						},
					},
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
			s.createHandlerV3(tt.args.in0, tt.args.r, tt.args.name, tt.args.ch)
		})
	}
}
