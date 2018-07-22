// pgcrtauth is a simple tool for generation of self-signed certificates for standalone
// and clustered PostgreSQL servers.
// Implementations of subcommands live in cmd package.
package main

import (
	"github.com/quasoft/pgcrtauth/cmd"
)

func main() {
	// Invoke the root command. See "https://github.com/spf13/cobra" for details.
	cmd.Execute()
}
