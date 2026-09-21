package config

import "github.com/spf13/viper"

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("server.ops_addr", ":9090")
	v.SetDefault("server.read_timeout", "5s")
	v.SetDefault("server.write_timeout", "10s")
	v.SetDefault("server.shutdown_grace", "15s")
	v.SetDefault("server.secure_cookies", true)

	v.SetDefault("mysql.max_open_conns", 25)
	v.SetDefault("mysql.max_idle_conns", 25)
	v.SetDefault("mysql.conn_max_lifetime", "5m")

	v.SetDefault("redis.enabled", true)
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 50)
	v.SetDefault("redis.dial_timeout", "1s")
	v.SetDefault("redis.read_timeout", "500ms")

	v.SetDefault("cache.negative_ttl", "1s")
	v.SetDefault("cache.service_ttl", "60s")

	v.SetDefault("tokens.default_lifetime", "45m")
	v.SetDefault("tokens.default_rotate_after", "15m")
	v.SetDefault("tokens.max_lifetime", "24h")

	v.SetDefault("ratelimit.issuance_per_minute", 60)
	v.SetDefault("ratelimit.introspect_per_minute", 60000)

	v.SetDefault("security.argon2.memory_kib", 65536)
	v.SetDefault("security.argon2.iterations", 3)
	v.SetDefault("security.argon2.parallelism", 4)
	v.SetDefault("security.argon2.salt_length", 16)
	v.SetDefault("security.argon2.key_length", 32)

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.sample_initial", 100)
	v.SetDefault("log.sample_thereafter", 100)
}

func bindEnvKeys(v *viper.Viper) {
	keys := []string{
		"server.addr",
		"server.ops_addr",
		"server.admin_api_key",
		"server.secure_cookies",
		"mysql.dsn",
		"redis.enabled",
		"redis.addr",
		"redis.password",
		"log.level",
		"log.format",
	}
	for _, k := range keys {
		_ = v.BindEnv(k)
	}
}
