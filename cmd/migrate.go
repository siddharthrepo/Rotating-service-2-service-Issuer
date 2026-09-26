package cmd

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/spf13/cobra"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/migrations"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/config"
	repomysql "github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/repository/mysql"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply database migrations",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all pending migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, closeFn, err := newMigrator()
		if err != nil {
			return err
		}
		defer closeFn()

		if err := m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("no pending migrations")
				return nil
			}
			return fmt.Errorf("migrate up: %w", err)
		}
		fmt.Println("migrations applied")
		return nil
	},
}

var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Roll back the most recent migration",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, closeFn, err := newMigrator()
		if err != nil {
			return err
		}
		defer closeFn()

		if err := m.Steps(-1); err != nil {
			return fmt.Errorf("migrate down: %w", err)
		}
		fmt.Println("rolled back one migration")
		return nil
	},
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current schema version",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, closeFn, err := newMigrator()
		if err != nil {
			return err
		}
		defer closeFn()

		version, dirty, err := m.Version()
		if errors.Is(err, migrate.ErrNilVersion) {
			fmt.Println("no migrations applied yet")
			return nil
		}
		if err != nil {
			return fmt.Errorf("migrate version: %w", err)
		}
		fmt.Printf("version: %d  dirty: %t\n", version, dirty)
		return nil
	},
}

func newMigrator() (*migrate.Migrate, func(), error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, nil, err
	}

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, nil, fmt.Errorf("open embedded migrations: %w", err)
	}

	db, err := repomysql.Open(cfg.MySQL)
	if err != nil {
		return nil, nil, err
	}

	driver, err := mysql.WithInstance(db.DB, &mysql.Config{})
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "mysql", driver)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("build migrator: %w", err)
	}
	return m, func() { db.Close() }, nil
}

func init() {
	migrateCmd.AddCommand(migrateUpCmd, migrateDownCmd, migrateStatusCmd)
	rootCmd.AddCommand(migrateCmd)
}
