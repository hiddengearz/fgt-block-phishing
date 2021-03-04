package cmd

import (
	"crypto/tls"
	"net/http"
	"os"

	l "github.com/hiddengearz/fgt-block-phishing/internal/logger"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	username string
	password string
	host     string
	email    string
	cfgFile  string
	key      string
	url      string
	Debug    bool

	RootCmd = &cobra.Command{
		Use:   "main",
		Short: "main",
		Long:  ``,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			f, err := os.OpenFile("log.info", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				log.Fatal(err)
			}
			if Debug {

				l.InitDetailedLogger(f)
				log.SetLevel(logrus.DebugLevel)

				log.Debug("Debug mode enabled")
			}
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "Enable Debug mode")
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

}

func Execute() error {
	return RootCmd.Execute()
}

func initConfig() {
	home, err := homedir.Dir()
	if err != nil {
		log.Fatal(err)
	}

	if cfgFile != "" { // Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else { //default is to check the home dir ~/fortinet-automation/config.yaml
		// Find home directory.

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home + "/fortinet-automation/")
		viper.SetConfigName("config.yaml")
		viper.SetConfigType("yaml")
	}

	//viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil { //read the config
		log.Debug("Using config file:", viper.ConfigFileUsed())
	} else { //otherwise create a config file in the default location
		log.Error(err)

		path := home + "/fortinet-automation/"

		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			os.Mkdir(path, 0700)
		}

		log.Info("creating config file at ", path+"config.yaml")

		err = viper.SafeWriteConfigAs(path + "config.yaml")
		if err != nil {
			log.Fatal(err)
		}

		initConfig()

	}

}
