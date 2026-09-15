// Command sundiata is the QYVORA cloud security assessment framework.
package main

import (
	"os"

	"github.com/QYVORA/qyvora-sundiata/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
