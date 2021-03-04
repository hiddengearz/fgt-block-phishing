package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hiddengearz/fgt-block-phishing/internal"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {

	AddCmd.PersistentFlags().StringVarP(&username, "username", "u", "default", "username used to log into (required)")
	AddCmd.PersistentFlags().StringVarP(&password, "password", "p", "default", "password (required)")
	AddCmd.PersistentFlags().StringVarP(&host, "host", "a", "", "host (required)")
	AddCmd.PersistentFlags().StringVarP(&key, "key", "k", "default", "key (required)")

	//AddCmd.MarkFlagRequired("username")
	//AddCmd.MarkFlagRequired("password")
	//AddCmd.MarkFlagRequired("host")
	AddCmd.MarkFlagRequired("key")

	AddCmd.AddCommand(FortimailCmd)
	AddCmd.AddCommand(FortigateCmd)
	RootCmd.AddCommand(AddCmd)
}

var AddCmd = &cobra.Command{
	Use:   "add",
	Short: "add",
	Long:  ``,
}

var FortimailCmd = &cobra.Command{
	Use:   "fortimail",
	Short: "fml",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log.Debug("FortimailCmd executed")
		//fmt.Println(password)
		fortimail := internal.Fortimail{Url: host, Username: username, Password: password}
		err := fortimail.AddToDB(key)
		if err != nil {
			log.Error(err)
		}

	},
}

var FortigateCmd = &cobra.Command{
	Use:   "fortigate",
	Short: "fgt",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log.Debug("FortigateCmd executed")

		fortigate := internal.FortiGate{}

		fmt.Print("Fortigate Address: ")
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		// convert CRLF to LF

		fortigate.Url = strings.Replace(text, "\n", "", -1)

		fmt.Print("Fortigate Token: ")
		text, _ = reader.ReadString('\n')
		fortigate.Token = strings.Replace(text, "\n", "", -1)

		fortigate.GetUrlFilters()
		//fortigate.IDsToBlock()
	},
}
