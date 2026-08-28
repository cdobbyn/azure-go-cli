package auth

import (
	"context"
	"os"

	"github.com/cdobbyn/azure-go-cli/pkg/logger"
	"github.com/spf13/cobra"
)

func NewLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to Azure",
		Long:  "Log in to Azure using device code flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Login prints no machine-readable output, so its progress lines go
			// to stdout. On stderr, PowerShell wraps every one of them in a
			// NativeCommandError and a successful login looks like a failure.
			logger.SetOutput(os.Stdout)

			tenantSelection, _ := cmd.Flags().GetBool("tenant-selection")
			subscription, _ := cmd.Flags().GetString("subscription")
			tenant, _ := cmd.Flags().GetString("tenant")
			useAzureCLI, _ := cmd.Flags().GetBool("use-azure-cli")
			return Login(context.Background(), tenantSelection, subscription, tenant, useAzureCLI)
		},
	}

	cmd.Flags().Bool("tenant-selection", false, "Always show tenant selection (useful with many subscriptions)")
	cmd.Flags().StringP("tenant", "t", "", "Tenant ID or domain to sign in to (prompts for subscription unless --subscription is given)")
	cmd.Flags().Bool("use-azure-cli", false, "Borrow tokens from the Python Azure CLI (az) instead of signing in directly - satisfies device-based Conditional Access via its WAM broker on Windows")

	return cmd
}

func NewLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "logout",
		Aliases: []string{"logoff"},
		Short:   "Log out from Azure",
		Long:    "Clear stored Azure credentials and log out",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Logout()
		},
	}
}
