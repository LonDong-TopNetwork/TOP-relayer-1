package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"toprelayer/relayer/toprelayer/ethashapp"
	"toprelayer/util"

	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
)

var (
	app = cli.NewApp()

	nodeFlags = []cli.Flag{
		&util.PasswordFileFlag,
		&util.ConfigFileFlag,
	}
)

func init() {
	app.Name = filepath.Base(os.Args[0])
	app.Usage = "the TOP-relayer command line interface"
	app.Copyright = "2017-present Telos Foundation & contributors"
	app.Action = start
	app.Flags = nodeFlags
}

func main() {
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("Run relayer error:", err)
		os.Exit(1)
	}
}

func start(ctx *cli.Context) error {
	for i := 1; i <= 1024; i++ {
		hash, err := ethashapp.CalcDagRoot(uint64(i))
		if err != nil {
			continue
		}
		fmt.Println(common.Bytes2Hex(hash))
	}
	return nil
}
