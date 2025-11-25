package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Suhaibinator/SuhaibServer/server"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config-file>\n", os.Args[0])
		os.Exit(1)
	}

	configFilePath := os.Args[1]
	if err := server.RunWithConfigFile(context.Background(), configFilePath); err != nil {
		panic(err)
	}
}
