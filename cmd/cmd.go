package cmd

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/macophub/macop/envconfig"
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
		Short:         "Model context protocol runner",
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

	//listCmd := &cobra.Command{
	//	Use:     "list",
	//	Aliases: []string{"ls"},
	//	Short:   "List MCP",
	//	PreRunE: checkServerHeartbeat,
	//	RunE:    ListHandler,
	//}

	serveCmd := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"start"},
		Short:   "Start macop",
		Args:    cobra.ExactArgs(0),
		RunE:    RunServer,
	}

	//pullCmd := &cobra.Command{
	//	Use:     "pull MCP",
	//	Short:   "Pull a mcp from a registry",
	//	Args:    cobra.ExactArgs(1),
	//	PreRunE: checkServerHeartbeat,
	//	RunE:    PullHandler,
	//}

	//pullCmd.Flags().Bool("insecure", false, "Use an insecure registry")

	envVars := envconfig.AsMap()
	envs := []envconfig.EnvVar{envVars["MACOP_HOST"]}

	for _, cmd := range []*cobra.Command{
		//pullCmd,
		serveCmd,
	} {
		switch cmd {
		case serveCmd:
			appendEnvDocs(cmd, []envconfig.EnvVar{
				envVars["MACOP_DEBUG"],
				envVars["MACOP_HOST"],
				envVars["MACOP_KEEP_ALIVE"],
				envVars["MACOP_MAX_LOADED_MCPS"],
				envVars["MACOP_MAX_QUEUE"],
				envVars["MACOP_MCPS"],
				envVars["MACOP_NUM_PARALLEL"],
				envVars["MACOP_NOPRUNE"],
				envVars["MACOP_ORIGINS"],
				envVars["MACOP_SCHED_SPREAD"],
				envVars["MACOP_TMPDIR"],
				envVars["MACOP_FLASH_ATTENTION"],
				envVars["MACOP_KV_CACHE_TYPE"],
				envVars["MACOP_LLM_LIBRARY"],
				envVars["MACOP_GPU_OVERHEAD"],
				envVars["MACOP_LOAD_TIMEOUT"],
			})
		default:
			appendEnvDocs(cmd, envs)
		}
	}

	rootCmd.AddCommand(
		serveCmd,
		//pullCmd,
	)
	return rootCmd
}

func appendEnvDocs(cmd *cobra.Command, envs []envconfig.EnvVar) {
	if len(envs) == 0 {
		return
	}

	envUsage := `
Environment Variables:
`
	for _, e := range envs {
		envUsage += fmt.Sprintf("      %-24s   %s\n", e.Name, e.Description)
	}

	cmd.SetUsageTemplate(cmd.UsageTemplate() + envUsage)
}
