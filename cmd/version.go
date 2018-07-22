package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print app name and version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("pgcrtauth v0.1.0")
	},
}
