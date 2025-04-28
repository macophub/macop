package cmd

import (
	"log"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/containerd/console"
)

func NewCLI() *cobra.Command {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	cobra.EnableCommandSorting = false
	if runtime.GOOS == "windows" && term.IsTerminal(int(os.Stdout.Fd())) {
		console.ConsoleFromFile(os.Stdin) //nolint:errcheck
	}

	rootCmd := &cobra.Command{
		Use:           "macop",
		Short:         "Model agent context operation platform",
		SilenceUsage:  true,
		SilenceErrors: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			if version, _ := cmd.Flags().GetBool("version"); version {
				//versionHandler(cmd, args)
				return
			}

			cmd.Print(cmd.UsageString())
		},
	}
	rootCmd.Flags().BoolP("version", "v", false, "Show version information")

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a mcp from a Mcpfile",
		RunE:  CreateHandler,
	}
	createCmd.Flags().StringP("file", "f", "", "Name of the Mcpfile (default \"Mcpfile\"")

	pushCmd := &cobra.Command{
		Use:   "push",
		Short: "push a mcp",
		RunE:  PushHandler,
	}
	pushCmd.Flags().StringP("image", "i", "", "Image")
	pushCmd.Flags().BoolP("insecure", "n", false, "insecure")
	pushCmd.Flags().StringP("username", "u", "", "username")
	pushCmd.Flags().StringP("password", "p", "", "password")

	pullCmd := &cobra.Command{
		Use:   "pull",
		Short: "pull a mcp",
		RunE:  PullHandler,
	}
	pullCmd.Flags().StringP("image", "i", "", "Image")
	pullCmd.Flags().BoolP("insecure", "n", false, "insecure")
	pullCmd.Flags().StringP("username", "u", "", "username")
	pullCmd.Flags().StringP("password", "p", "", "password")

	rootCmd.AddCommand(
		createCmd,
		pushCmd,
		pullCmd,
	)
	return rootCmd
}
