package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "kubernetes",
		Usage: "sshpiperd kubernetes plugin",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "all-namespaces",
				Usage:    "To watch all namespaces in the cluster",
				EnvVars:  []string{"SSHPIPERD_KUBERNETES_ALL_NAMESPACES"},
				Required: false,
			},
			&cli.BoolFlag{
				Name: "allow-password-auth",
				Usage: "Saturn: offer password login for Pipe `from` entries that have no authorized keys. " +
					"Off by default: such an entry then denies every login, and the plugin offers only publickey.",
				EnvVars:  []string{"SSHPIPERD_KUBERNETES_ALLOW_PASSWORD_AUTH"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "kubeconfig",
				Usage:    "Path to kubeconfig file",
				EnvVars:  []string{"SSHPIPERD_KUBERNETES_KUBECONFIG", "KUBECONFIG"},
				Required: false,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			plugin, err := newKubernetesPlugin(c.Bool("all-namespaces"), c.String("kubeconfig"))
			if err != nil {
				return nil, err
			}
			plugin.allowPasswordAuth = c.Bool("allow-password-auth")
			return plugin.createConfig(), nil
		},
	})
}
