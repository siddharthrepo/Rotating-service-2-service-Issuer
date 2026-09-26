// Package config resolves configuration from flags, environment, and file.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

// Load resolves flags -> env (S2S_ prefix) -> file -> defaults.
func Load(cfgFile string) (*structs.Config, error) {
	v := viper.New()
	setDefaults(v)

	v.SetEnvPrefix("S2S")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	bindEnvKeys(v)

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %s: %w", cfgFile, err)
		}
	}

	var c structs.Config
	if err := v.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := Validate(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate catches misconfigurations that would otherwise surface as confusing
// runtime behaviour rather than a startup failure.
func Validate(c *structs.Config) error {
	if c.MySQL.DSN == "" {
		return fmt.Errorf("mysql.dsn is required (set S2S_MYSQL_DSN)")
	}
	if c.Server.AdminAPIKey == "" {
		return fmt.Errorf("server.admin_api_key is required (set S2S_SERVER_ADMIN_API_KEY): " +
			"the admin surface must never be unauthenticated")
	}
	if c.Tokens.DefaultRotateAfter >= c.Tokens.DefaultLifetime {
		return fmt.Errorf("tokens.default_rotate_after (%s) must be less than default_lifetime (%s): "+
			"their difference is the rotation overlap window",
			c.Tokens.DefaultRotateAfter, c.Tokens.DefaultLifetime)
	}
	if c.Tokens.DefaultLifetime > c.Tokens.MaxLifetime {
		return fmt.Errorf("tokens.default_lifetime (%s) exceeds max_lifetime (%s)",
			c.Tokens.DefaultLifetime, c.Tokens.MaxLifetime)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("log.format must be json or text, got %q", c.Log.Format)
	}
	if c.Log.SampleInitial > 0 && c.Log.SampleThereafter <= 0 {
		return fmt.Errorf("log.sample_thereafter must be positive when sampling is enabled; " +
			"set log.sample_initial to 0 to disable sampling entirely")
	}
	return nil
}
