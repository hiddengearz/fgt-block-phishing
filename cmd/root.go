package cmd

RootCmd = &cobra.Command{
	Use:   "main",
	Short: "main",
	Long:  ``,
	
}


func Execute() error {
	return RootCmd.Execute()
}