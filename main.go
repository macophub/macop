package main

import (
	"context"

	"github.com/macophub/macop/cmd"
	"github.com/spf13/cobra"
)

func main() {
	cobra.CheckErr(cmd.NewCLI().ExecuteContext(context.Background()))
}
