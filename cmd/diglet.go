// Package cmd contains primary CLI commands and flag logic
package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"git.l.yamlinson.com/ryan/netgo/internal/dns"
	"github.com/spf13/cobra"
)

// digletCmd represents the diglet command
var (
	serv      string
	port      int
	typeFlag  string
	digletCmd = &cobra.Command{
		Use:   "diglet",
		Short: "Diglet is a simple DNS client",
		Args:  cobra.ExactArgs(1),
		RunE:  runDiglet,
	}
)

func init() {
	rootCmd.AddCommand(digletCmd)
	digletCmd.PersistentFlags().StringVarP(&serv, "server", "s", "9.9.9.9", "DNS server address")
	digletCmd.PersistentFlags().IntVarP(&port, "port", "p", 53, "DNS server port")
	digletCmd.PersistentFlags().StringVarP(&typeFlag, "type", "t", "A", "query type")
}

func runDiglet(cmd *cobra.Command, args []string) error {
	qtypes := map[string]uint16{
		"A":     1,
		"NS":    2,
		"MD":    3,
		"MF":    4,
		"CNAME": 5,
		"SOA":   6,
		"MB":    7,
		"MG":    8,
		"MR":    9,
		"NULL":  10,
		"WKS":   11,
		"PTR":   12,
		"HINFO": 13,
		"MINFO": 14,
		"MX":    15,
		"TXT":   16,
		"AXFR":  252,
		"MAILB": 253,
		"MAILA": 254,
		"*":     255,
	}

	qtype, ok := qtypes[strings.ToUpper(typeFlag)]
	if !ok {
		return fmt.Errorf("unsupported query type: %s", typeFlag)
	}

	server := fmt.Sprintf("%s:%d", serv, port)
	name := args[0]

	slog.Debug("received flags", "type", qtype, "name", name, "server", server)

	res, err := dns.Query(name, qtype, server)
	if err != nil {
		return err
	}

	fmt.Print(res)

	return nil
}
