package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// runInitialSetup creates initial credentials only. Existing files are never
// overwritten; migrations must retain their existing key and password hash.
func runInitialSetup(args []string, readPassword func(string) ([]byte, error), out io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("env-file", "", "write credentials to a new private file instead of printing them")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: nexus setup [--env-file NEW-FILE]")
	}
	if *path != "" {
		if _, err := os.Lstat(*path); !os.IsNotExist(err) {
			return errors.New("setup requires a new configuration file")
		}
	}
	pw, err := readPassword("Enter password (12–72 bytes): ")
	if err != nil {
		return err
	}
	defer clear(pw)
	if len(pw) < 12 || len(pw) > 72 {
		return errors.New("password must contain 12–72 bytes")
	}
	again, err := readPassword("Confirm password: ")
	if err != nil {
		return err
	}
	defer clear(again)
	if string(pw) != string(again) {
		return errors.New("passwords do not match")
	}
	hash, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		return errors.New("could not hash password")
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	data := []byte(fmt.Sprintf("NEXUS_PASSWORD_HASH='%s'\nNEXUS_ENCRYPTION_KEY=%s\n", hash, base64.StdEncoding.EncodeToString(key)))
	defer clear(data)
	if *path == "" {
		_, err = out.Write(data)
		return err
	}
	file, err := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("could not create private configuration file")
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return errors.New("configuration write failed; remove the incomplete file before retrying")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("configuration sync failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("configuration close failed")
	}
	_, err = fmt.Fprintln(out, "Initial configuration saved. Keep this file private and include it in backups.")
	return err
}
