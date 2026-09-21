// Package cmd wires the CLI.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "s2s",
	Short: "Rotating service-to-service token issuer",
	Long: `s2s issues short-lived, automatically rotated tokens for service-to-service
authentication, replacing per-pair shared secrets with one identity per service.

Tokens are issued per grant (a caller -> target relationship), not per pod, and
rotate on a schedule with a configurable overlap so rotation never drops traffic.`,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default: environment only, S2S_ prefix)")
}
