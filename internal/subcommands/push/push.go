package push

import (
	"context"

	"github.com/spf13/cobra"
)

type MacopPushCommand struct {
	filename string
}

func (x *MacopPushCommand) doPush(ctx context.Context) error {

}

func (x *MacopPushCommand) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push a macOS app to the Mac App Store",
		Long:  `Push a macOS app to the Mac App Store.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return x.doPush(cmd.Context())
		},
	}
	cmd.Flags().StringVarP(&x.filename, "filepath", "f", "", "The path to the macop file to be pushed")
	return cmd
}
