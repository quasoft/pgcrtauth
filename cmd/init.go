package cmd

import (
	"os"

	"github.com/quasoft/pgcrtauth/crtauth"
	"github.com/spf13/cobra"
)

type initFlags struct {
	organization string
	commonName   string
	validForDays int
	keySize      string
	caDir        string
}

var in initFlags

func init() {
	initCmd.Flags().SortFlags = false
	initCmd.Flags().StringVarP(&in.organization, "organization", "O", "", "Subject's organization name (default empty)")
	initCmd.Flags().StringVarP(&in.commonName, "common-name", "C", "", "Subject's common name (default empty)")
	initCmd.Flags().IntVarP(&in.validForDays, "valid-for", "V", 365, "How many days the certificate will be valid for from now on")
	initCmd.Flags().StringVarP(&in.keySize, "key-size", "K", "P256", "One of P224, P256, P384, P521, 1024, 2048, 3072, 4096")
	initCmd.Flags().StringVarP(&in.caDir, "ca-dir", "c", "", "The directory in which the generated root files should be stored")
	initCmd.MarkFlagRequired("ca-dir")
	rootCmd.AddCommand(initCmd)
}

var initCmd = &cobra.Command{
	Use:   "init --ca-dir <directory>",
	Short: "Creates a new certificate authority (root.crt and root.key files) in an empty directory",
	Long: `Creates a new certificate authority (root.crt and root.key files) in the specified directory.
Existing root files in the '--ca-dir' directory will be overwritten.
The choice of key size determines the cryptograghy algorithm to use.
  Elliptic curve cryptograghy:
  - P224, P256, P384, P521
  RSA:
  - 1024, 2048, 3072, 4096
`,
	Example: `  Create root files in /certs/ca with default parameters:
    pgcrtauth init --ca-dir /certs/ca

  Create root files in /certs/ca with RSA key of 2048 bits and custom names:
    pgcrtauth init --organization "MyCompany" --common-name "DBClusterCA" -K 2048 --ca-dir /certs/ca
`,
	Run: func(cmd *cobra.Command, args []string) {
		keyBits, err := parseKeyBits(in.keySize)
		if err != nil {
			cmd.Printf("Bad key size: %s\n", err)
			os.Exit(1)
		}

		cmd.Printf("Creating a new certificate authority at %s\n", in.caDir)

		template := crtauth.NewTemplate()
		template.Organization = in.organization
		template.CommonName = in.commonName
		template.ValidForDays = in.validForDays
		template.KeyBits = keyBits

		ca := crtauth.New()
		err = ca.Init(template, in.caDir)
		if err != nil {
			cmd.Printf("Could not create certification authority: %s\n", err)
			os.Exit(1)
		}

		cmd.Println("Successfully created certification authority.")
		cmd.Println("Done")
	},
}
