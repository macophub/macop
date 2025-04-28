package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/shlex"
)

type Macop struct {
	config    MacopConfig
	configDIR string
}

type MacopConfig struct {
	Version  string `yaml:"version"`
	Metadata MacopConfigMeta
	Spec     MacopConfigSpec
}

type MacopConfigSpec struct {
	Entrypoint string   `yaml:"entrypoint"`
	Cmd        []string `yaml:"cmd"`
	Files      MacopConfigSpecFiles
	Builds     []MacopConfigSpecBuild
}

type MacopConfigMeta struct {
	McpType string `yaml:"mcpType"`
	Image   string `yaml:"image"`
}

type MacopConfigSpecFiles struct {
	Copy []MacopConfigSpecFileCopy
}
type MacopConfigSpecFileCopy struct {
	Src string `yaml:"src"`
	Dst string `yaml:"dst"`
}
type MacopConfigSpecBuild struct {
	Architecture string `yaml:"architecture"`
	Os           string `yaml:"os"`
	BuildCMD     string `yaml:"buildCMD"`
	BinFilepath  string `yaml:"binFilepath"`
}

func (x *Macop) Build(ctx context.Context) error {
	for _, build := range x.config.Spec.Builds {
		if build.BinFilepath == "" {
			return fmt.Errorf("binFilepath is empty")
		}

		cmd, err := parseCommand(ctx, build.BuildCMD)
		if err != nil {
			return fmt.Errorf("failed to parse build command: err=%w, command=%s", err, build.BuildCMD)
		}
		cmd.Dir = x.configDIR
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to run build command: err=%w, command=%s", err, build.BuildCMD)
		}

	}
	return nil
}

func (x *Macop) Push(ctx context.Context) error {
	return nil
}
func (x *Macop) Pull(ctx context.Context) error {
	return nil
}
func (x *Macop) Run(ctx context.Context, args []string) error {
	return nil
}
func (x *Macop) Remove(ctx context.Context, args []string) error {
	return nil
}

func parseCommand(ctx context.Context, cmdStr string) (*exec.Cmd, error) {
	args, err := shlex.Split(cmdStr)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	return exec.CommandContext(ctx, args[0], args[1:]...), nil
}
