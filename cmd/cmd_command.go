package cmd

import (
	"fmt"
	"os"

	"github.com/macophub/macop/internal/core"
	"github.com/spf13/cobra"
)

func CreateHandler(cmd *cobra.Command, args []string) error {
	// 获取 file 标志的值
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return fmt.Errorf("failed to get 'file' flag: %w", err)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	macop, err := core.NewMacop(content)
	if err != nil {
		return fmt.Errorf("failed to create macop: %w", err)
	}
	ch := make(chan any, 1024)
	err = macop.Create(cmd.Context(), ch)
	if err != nil {
		return fmt.Errorf("failed to create macop2: %w", err)
	}
	return nil
}

func PushHandler(cmd *cobra.Command, args []string) error {
	// 获取 file 标志的值
	image, err := cmd.Flags().GetString("image")
	if err != nil {
		return fmt.Errorf("failed to get 'image' flag: %w", err)
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return fmt.Errorf("failed to get 'insecure' flag: %w", err)
	}
	username, err := cmd.Flags().GetString("username")
	if err != nil {
		return fmt.Errorf("failed to get 'username' flag: %w", err)
	}
	password, err := cmd.Flags().GetString("password")
	if err != nil {
		return fmt.Errorf("failed to get 'password' flag: %w", err)
	}

	macop, err := core.NewMacopByPullOrPush(image)
	if err != nil {
		return fmt.Errorf("failed to create macop: %w", err)
	}
	ch := make(chan any, 1024)
	err = macop.Push(cmd.Context(), core.PushRequest{
		Insecure: insecure,
		Username: username,
		Password: password,
	}, ch)
	if err != nil {
		return fmt.Errorf("failed to create macop2: %w", err)
	}
	return nil
}

func PullHandler(cmd *cobra.Command, args []string) error {
	// 获取 file 标志的值
	image, err := cmd.Flags().GetString("image")
	if err != nil {
		return fmt.Errorf("failed to get 'image' flag: %w", err)
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return fmt.Errorf("failed to get 'insecure' flag: %w", err)
	}
	username, err := cmd.Flags().GetString("username")
	if err != nil {
		return fmt.Errorf("failed to get 'username' flag: %w", err)
	}
	password, err := cmd.Flags().GetString("password")
	if err != nil {
		return fmt.Errorf("failed to get 'password' flag: %w", err)
	}

	macop, err := core.NewMacopByPullOrPush(image)
	if err != nil {
		return fmt.Errorf("failed to create macop: %w", err)
	}
	ch := make(chan any, 1024)
	err = macop.Pull(cmd.Context(), core.PullRequest{
		Insecure: insecure,
		Username: username,
		Password: password,
	}, ch)
	if err != nil {
		return fmt.Errorf("failed to create macop2: %w", err)
	}
	return nil
}
