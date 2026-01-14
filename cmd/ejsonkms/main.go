package main

import (
	"fmt"
	"os"

	"github.com/envato/ejsonkms"
	"github.com/urfave/cli"
)

// version information. This will be overridden by the ldflags
var version = "dev"

// fail prints the error message to stderr, then ends execution.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %s\n", err)
	os.Exit(1)
}

func main() {
	app := cli.NewApp()
	app.Usage = "manage encrypted secrets using EJSON & AWS KMS"
	app.Version = version
	app.Author = "Steve Hodgkiss"
	app.Email = "steve@envato.com"
	app.Commands = []cli.Command{
		{
			Name:  "encrypt",
			Usage: "(re-)encrypt one or more EJSON files",
			Action: func(c *cli.Context) {
				if err := ejsonkms.EncryptAction(c.Args()); err != nil {
					fmt.Fprintln(os.Stderr, "Encryption failed:", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "decrypt",
			Usage: "decrypt an EJSON file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "o",
					Usage: "print output to the provided file, rather than stdout",
				},
				cli.StringFlag{
					Name:   "aws-region",
					Usage:  "AWS Region",
					EnvVar: "AWS_REGION,AWS_DEFAULT_REGION",
				},
			},
			Action: func(c *cli.Context) {
				if err := ejsonkms.DecryptAction(c.Args(), c.String("aws-region"), c.String("o")); err != nil {
					fmt.Fprintln(os.Stderr, "Decryption failed:", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "keygen",
			Usage: "generate a new EJSON keypair",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "kms-key-id",
					Usage: "KMS Key ID to encrypt the private key with",
				},
				cli.StringFlag{
					Name:   "aws-region",
					Usage:  "AWS Region",
					EnvVar: "AWS_REGION,AWS_DEFAULT_REGION",
				},
				cli.StringFlag{
					Name:  "o",
					Usage: "write EJSON file to a file rather than stdout",
				},
			},
			Action: func(c *cli.Context) {
				if err := ejsonkms.KeygenAction(c.Args(), c.String("kms-key-id"), c.String("aws-region"), c.String("o")); err != nil {
					fmt.Fprintln(os.Stderr, "Key generation failed:", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "env",
			Usage: "print shell export statements",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "quiet, q",
					Usage: "Suppress export statement",
				},
				cli.StringFlag{
					Name:   "aws-region",
					Usage:  "AWS Region",
					EnvVar: "AWS_REGION,AWS_DEFAULT_REGION",
				},
			},
			Action: func(c *cli.Context) {
				var filename string

				quiet := c.Bool("quiet")
				awsRegion := c.String("aws-region")

				if 1 <= len(c.Args()) {
					filename = c.Args().Get(0)
				}

				if "" == filename {
					fail(fmt.Errorf("no secrets.ejson filename passed"))
				}

				if err := ejsonkms.EnvAction(filename, awsRegion, quiet); nil != err {
					fail(err)
				}
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "Unexpected failure:", err)
		os.Exit(1)
	}
}
