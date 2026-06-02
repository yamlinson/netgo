// Package cmd contains primary CLI commands and flag logic
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// digletCmd represents the diglet command
var digletCmd = &cobra.Command{
	Use:   "diglet",
	Short: "Diglet is a simple DNS client",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("diglet called")
	},
}

func init() {
	rootCmd.AddCommand(digletCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// digletCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// digletCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
