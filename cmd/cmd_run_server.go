package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/macophub/macop/server"
	"golang.org/x/crypto/ssh"

	"github.com/macophub/macop/envconfig"
	"github.com/spf13/cobra"
)

func RunServer(_ *cobra.Command, _ []string) error {
	if err := initializeKeypair(); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", envconfig.Host().Host)
	if err != nil {
		return err
	}

	err = server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

func initializeKeypair() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	privKeyPath := filepath.Join(home, ".macop", "id_ed25519")
	pubKeyPath := filepath.Join(home, ".macop", "id_ed25519.pub")

	_, err = os.Stat(privKeyPath)
	if os.IsNotExist(err) {
		fmt.Printf("Couldn't find '%s'. Generating new private key.\n", privKeyPath)
		cryptoPublicKey, cryptoPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}

		privateKeyBytes, err := ssh.MarshalPrivateKey(cryptoPrivateKey, "")
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(privKeyPath), 0o755); err != nil {
			return fmt.Errorf("could not create directory %w", err)
		}

		if err := os.WriteFile(privKeyPath, pem.EncodeToMemory(privateKeyBytes), 0o600); err != nil {
			return err
		}

		sshPublicKey, err := ssh.NewPublicKey(cryptoPublicKey)
		if err != nil {
			return err
		}

		publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)

		if err := os.WriteFile(pubKeyPath, publicKeyBytes, 0o644); err != nil {
			return err
		}

		fmt.Printf("Your new public key is: \n\n%s\n", publicKeyBytes)
	}
	return nil
}
