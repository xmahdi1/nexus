package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xmahdi1/nexus/internal/db"
)

func runKeyRotate(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("key-rotate", flag.ContinueOnError)
	flags.SetOutput(out)
	keyFile := flags.String("key-file", "", "private file containing the current base64 key; never supply key bytes on argv")
	stopped := flags.Bool("offline", false, "confirm Nexus is stopped and remains stopped through manual promotion")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*stopped || *keyFile == "" || flags.NArg() != 2 {
		return fmt.Errorf("usage: nexus key-rotate --offline --key-file CURRENT-KEY-FILE SOURCE.db NEW-RECOVERY-DIRECTORY")
	}
	file, err := os.Open(*keyFile)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("key file must be regular and private (mode 0600 or stricter)")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return err
	}
	defer clear(encoded)
	if len(encoded) > 4096 {
		return fmt.Errorf("invalid key file")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("key file must contain a base64-encoded 32-byte key")
	}
	defer clear(key)
	if err := db.RotateRecoverySet(flags.Arg(0), flags.Arg(1), key); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "Recovery set complete. Check READY and manifest.json. Original database/configuration unchanged. Keep Nexus stopped until the matching database and key are installed together; preserve the original pair for rollback. No workers started.")
	return err
}
