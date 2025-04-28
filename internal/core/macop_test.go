package core

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMacop(t *testing.T) {
	type args struct {
		content []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *Macop
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewMacop(tt.args.content)
			if !tt.wantErr(t, err, fmt.Sprintf("NewMacop(%v)", tt.args.content)) {
				return
			}
			assert.Equalf(t, tt.want, got, "NewMacop(%v)", tt.args.content)
		})
	}
}
