package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/quasoft/pgcrtauth/crtauth"
	"github.com/spf13/cobra"
)

type serverFlags struct {
	host         string
	organization string
	commonName   string
	validForDays int
	keySize      string
	outDir       string
	caDir        string
}

var server serverFlags

func init() {
	genCmd.Flags().SortFlags = false
	genCmd.Flags().StringVarP(&server.host, "hostnames", "H", "", "Comma separated IP addresses and hostnames of the server")
	genCmd.Flags().StringVarP(&server.organization, "organization", "O", "", "Subject's organization name (default empty)")
	genCmd.Flags().StringVarP(&server.commonName, "common-name", "C", "", "Subject's common name (default empty)")
	genCmd.Flags().IntVarP(&server.validForDays, "valid-for", "V", 365, "How many days the certificate will be valid for from now on")
	genCmd.Flags().StringVarP(&server.keySize, "key-size", "K", "P256", "One of P224, P256, P384, P521, 1024, 2048, 3072, 4096")
	genCmd.Flags().StringVarP(&server.outDir, "out-dir", "o", "", "Directory where generated files (server.crt/server.key) should be stored")
	genCmd.Flags().StringVarP(&server.caDir, "ca-dir", "c", "", "Directory containing root.crt and root.key files (created with 'pgcrtauth init' command)")
	genCmd.Flags().BoolP("self-signed", "s", false, "If set, a self-signed certificate is created, without using a CA")

	genCmd.MarkFlagRequired("hostnames")
	genCmd.MarkFlagRequired("out-dir")
	rootCmd.AddCommand(genCmd)
}

var genCmd = &cobra.Command{
	Use:   "generate --hostnames <string>[,<string>] --out-dir <directory> (--ca-dir <directory> | --self-signed yes)",
	Short: "Generates a server certificate pair for use by PostgreSQL (server.crt and server.key)",
	Long: `Generates a server certificate pair for use by PostgreSQL (server.crt and server.key).
If specified, the '--ca-dir' directory should contain root.crt and root.key files created with the 'pgcrtauth init' command.
Alternatively you can create a self-signed server certificate without using a CA. To do that set the --self-signed flag.
The choice of key size determines the cryptograghy algorithm to use.
  Elliptic curve cryptograghy:
  - P224, P256, P384, P521
  RSA:
  - 1024, 2048, 3072, 4096
`,
	Example: `  Generate a self-signed server certificate with default parameters:
    pgcrtauth generate -H "server1,10.0.0.1" --out-dir /certs/server1 --self-signed

  Generates a server certificate signed by /myCA/root.key file of the /myCA authority:
    pgcrtauth generate -H 10.0.0.1 -o /certs/server1 -ca /myCA

  Generate a self-signed server certificate with RSA key of 2048 bits:
    pgcrtauth generate -H "server2" -K 2048 --out-dir /certs/server2 --self-signed
`,
	Run: func(cmd *cobra.Command, args []string) {
		selfSigned := cmd.Flag("self-signed").Changed

		if server.caDir == "" && !selfSigned {
			cmd.Printf("At least one of --ca-dir or --self-signed arguments is required\n")
			os.Exit(1)
		}

		keyBits, err := parseKeyBits(in.keySize)
		if err != nil {
			cmd.Printf("Bad key size: %s\n", err)
			os.Exit(1)
		}

		template := crtauth.NewTemplate()
		template.Organization = server.organization
		template.CommonName = server.commonName
		template.HostNames = strings.Split(server.host, ",")
		template.ValidForDays = server.validForDays
		template.KeyBits = keyBits

		pair, err := crtauth.NewServerPair(template)
		if err != nil {
			cmd.Printf("Could not create cert/key pair: %s\n", err)
			os.Exit(1)
		}

		if selfSigned {
			// Self-sign
			cmd.Println("Creating a self-signed certificate")
			err = pair.SignWith(pair)
			if err != nil {
				cmd.Printf("Could not self-sign certificate: %s\n", err)
				os.Exit(1)
			}
		} else {
			// Sign with specified CA
			cmd.Printf("Creating a certificate signed by the CA at %s\n", server.caDir)
			ca := crtauth.New()
			err = ca.Load(server.caDir)
			if err != nil {
				cmd.Printf("Could not load CA pair from directory '%s': %s\n", server.caDir, err)
				os.Exit(1)
			}

			err = pair.SignWith(ca.Pair)
			if err != nil {
				cmd.Printf("Could not sign certificate with CA: %s\n", err)
				os.Exit(1)
			}
		}

		certPath := filepath.Join(server.outDir, crtauth.ServerCertFileName)
		keyPath := filepath.Join(server.outDir, crtauth.ServerKeyFileName)
		err = pair.WriteFiles(certPath, keyPath)
		if err != nil {
			cmd.Printf("Could not write cert/key pair to files: %s\n", err)
			os.Exit(1)
		}

		cmd.Println("Successfully created server pair at:")
		cmd.Printf("- Certificate: %s:\n", certPath)
		cmd.Printf("- Private key: %s:\n", keyPath)
		cmd.Println("Done")
	},
}
