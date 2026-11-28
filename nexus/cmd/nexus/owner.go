package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"golang.org/x/term"
)

func terminalPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return password, err
}

func runOwnerBootstrap(args []string, readPassword func(string) ([]byte, error), out io.Writer) error {
	flags := flag.NewFlagSet("owner-bootstrap", flag.ContinueOnError)
	flags.SetOutput(out)
	fromEnv := flags.Bool("from-env", false, "copy the configured legacy bcrypt hash without changing .env")
	path := flags.String("db", "", "SQLite path (defaults to configured path with --from-env)")
	display := flags.String("display-name", "", "owner display name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: nexus owner-bootstrap [--from-env] [--db DATABASE.db] [--display-name NAME] USERNAME")
	}
	username, err := identity.NormalizeUsername(flags.Arg(0))
	if err != nil {
		return err
	}
	var hash string
	var encryptionKey []byte
	if *fromEnv {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		hash = cfg.PasswordHash
		encryptionKey = cfg.EncryptionKey
		if *path == "" {
			*path = cfg.DBPath
		}
	} else {
		if *path == "" {
			return errors.New("--db is required unless --from-env is used")
		}
		password, err := readPassword("New owner password (12+ bytes): ")
		if err != nil {
			return err
		}
		defer clear(password)
		confirm, err := readPassword("Confirm owner password: ")
		if err != nil {
			return err
		}
		defer clear(confirm)
		if !bytes.Equal(password, confirm) {
			return errors.New("passwords do not match")
		}
		hash, err = identity.HashPassword(password)
		if err != nil {
			return err
		}
	}
	if err := identity.ValidatePasswordHash(hash); err != nil {
		return err
	}
	database, err := db.Init(*path, encryptionKey)
	if err != nil {
		return err
	}
	connection, err := database.DB()
	if err != nil {
		return err
	}
	defer connection.Close()
	result, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: username, DisplayName: *display, PasswordHash: hash})
	if err != nil {
		return err
	}
	if result.Created {
		fmt.Fprintf(out, "Owner account recorded: %s (%s).\n", result.User.Username, result.User.ID)
	} else {
		fmt.Fprintf(out, "Owner %s already exists; account and credentials unchanged.\n", result.User.Username)
	}
	var state auth.State
	if err := database.First(&state, "id=1").Error; err != nil {
		return err
	}
	if state.Mode == "owner" {
		fmt.Fprintln(out, "Owner account login is active; credentials were not changed.")
	} else {
		fmt.Fprintln(out, "Owner prepared. HTTP sign-in still uses the configured administrator and MFA until the explicit local owner-activate command.")
	}
	return nil
}
