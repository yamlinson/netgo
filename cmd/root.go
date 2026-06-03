// Package cmd contains primary CLI commands and flag logic
package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var (
	verbose bool
	rootCmd = &cobra.Command{
		Use:   "netgo",
		Short: "A collection of network utilities for terminal use",
		Long: `Netgo is a CLI network utility suite.
	It is primarily written as a learning opportunity for implementing common network-related utilities in Go.`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if verbose {
				slog.SetLogLoggerLevel(slog.LevelDebug)
			} else {
				slog.SetLogLoggerLevel(slog.LevelError)
			}
			return nil
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")
}
