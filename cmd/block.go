package cmd

import (
	"github.com/hiddengearz/fgt-block-phishing/internal"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	BlockCmd.PersistentFlags().StringVarP(&key, "key", "k", "default", "key (required)")
	BlockCmd.Flags().StringVarP(&host, "address", "a", "", "address (required)")
	BlockCmd.Flags().StringVarP(&email, "email", "e", "default", "email to block")
	BlockCmd.Flags().StringVarP(&url, "url", "u", "default", "email to block")

	//BlockCmd.MarkFlagRequired("username")
	BlockCmd.MarkFlagRequired("key")
	BlockCmd.MarkFlagRequired("url")

	RootCmd.AddCommand(BlockCmd)
}

var BlockCmd = &cobra.Command{
	Use:   "block",
	Short: "block",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		//var fortimails internal.Fortimails

		log.Debug("BlockCmd executed")
		/*
				if email == "" {
					log.Error("No email provied")
					return
				}
				fortimail := internal.Fortimail{
					Url:      "https://" + ip,
					Username: username,
					Password: password,
				}
				fortimail.Login()
				fortimail.AddToBlackList(email)


			if email != "" {
				err, fortimails := internal.GetFortimails(key)
				if err != nil {
					log.Error("No fortimails saved in config")
					return
				}

				for _, fortimail := range fortimails {
					err := fortimail.Login()
					if err != nil {
						log.Error("Unable to log into fortimail: " + fortimail.Url)
						return
					}
					err = fortimail.AddToBlackList(email)
					if err != nil {
						log.Error("Unable to block email: " + email + " on fortimail " + fortimail.Url)
						return
					}
				}
			}
		*/

		fortigate := internal.FortiGate{
			Url:   "https://" + host,
			Token: "",
		}
		fortigate.BlockURL()

	},
}
