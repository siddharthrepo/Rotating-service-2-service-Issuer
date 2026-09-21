package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/siddharth120604/rotating-s2s/pkg/config"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/repository/mysql"
	"github.com/siddharth120604/rotating-s2s/pkg/service"
)

var userRole string

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage dashboard operators",
}

var userCreateCmd = &cobra.Command{
	Use:   "create <email> <name>",
	Short: "Create a dashboard operator",
	Long: `Creates a human operator for the dashboard.

Dashboard accounts are entirely separate from service credentials: people sign
in with a password and get a session cookie, machines present client
credentials. This command exists because the first admin has to come from
somewhere other than the dashboard itself.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		db, err := mysql.Open(cfg.MySQL)
		if err != nil {
			return err
		}
		defer db.Close()

		password, err := readPassword()
		if err != nil {
			return err
		}

		auth := service.NewAuth(mysql.NewUserRepo(db),
			service.NewAudit(mysql.NewAuditRepo(db)), cfg.Security.Argon2)

		user, err := auth.CreateUser(context.Background(), args[0], args[1],
			password, constants.UserRole(userRole))
		if err != nil {
			return err
		}
		fmt.Printf("created %s (%s) with role %s\n", user.Email, user.Name, user.Role)
		return nil
	},
}

func readPassword() (string, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print("password: ")
		raw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		fmt.Print("confirm:  ")
		again, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		if string(raw) != string(again) {
			return "", fmt.Errorf("passwords do not match")
		}
		return string(raw), nil
	}

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading password from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func init() {
	userCreateCmd.Flags().StringVar(&userRole, "role", string(constants.RoleAdmin),
		"admin | operator | viewer  (viewers can see everything and change nothing)")
	userCmd.AddCommand(userCreateCmd)
	rootCmd.AddCommand(userCmd)
}
