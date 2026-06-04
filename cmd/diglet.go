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

var qtypes = map[string]uint16{
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

var qtypeNames = map[uint16]string{
	1:   "A",
	2:   "NS",
	3:   "MD",
	4:   "MF",
	5:   "CNAME",
	6:   "SOA",
	7:   "MB",
	8:   "MG",
	9:   "MR",
	10:  "NULL",
	11:  "WKS",
	12:  "PTR",
	13:  "HINFO",
	14:  "MINFO",
	15:  "MX",
	16:  "TXT",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA",
	255: "*",
}

func init() {
	rootCmd.AddCommand(digletCmd)
	digletCmd.PersistentFlags().StringVarP(&serv, "server", "s", "9.9.9.9", "DNS server address")
	digletCmd.PersistentFlags().IntVarP(&port, "port", "p", 53, "DNS server port")
	digletCmd.PersistentFlags().StringVarP(&typeFlag, "type", "t", "A", "query type")
}

func runDiglet(_ *cobra.Command, args []string) error {
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

	typ, ok := qtypeNames[qtype]
	if !ok {
		name = fmt.Sprintf("TYPE%d", qtype)
	}

	fmt.Println("----------------------------")
	fmt.Println("---------- diglet ----------")
	fmt.Println("----------------------------")
	fmt.Println("---       Questions      ---")
	fmt.Println("")
	fmt.Printf("Server: %s\n", server)
	fmt.Printf("Name: %s\n", name)
	fmt.Printf("Type: %s\n", strings.ToUpper(typeFlag))
	fmt.Println("")
	fmt.Println("----------------------------")
	fmt.Println("---        Answers       ---")
	fmt.Println("")
	fmt.Println("Type\tTTL\tName")
	for _, answer := range res.Answers {
		fmt.Printf("%s\t%d\t%s\n", typ, answer.TTL, answer.Name)
	}
	fmt.Println("")

	return nil
}
