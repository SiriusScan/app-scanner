module github.com/SiriusScan/app-scanner

go 1.22.0

toolchain go1.22.5

replace github.com/SiriusScan/go-api => ../go-api

require (
	github.com/SiriusScan/go-api v0.0.2
	github.com/lair-framework/go-nmap v0.0.0-20191202052157-3507e0b03523
	gorm.io/driver/postgres v1.5.2
	gorm.io/gorm v1.25.12
)

require (
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.3.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/streadway/amqp v1.1.0 // indirect
	github.com/tursodatabase/libsql-client-go v0.0.0-20240902231107-85af5b9d094d // indirect
	github.com/valkey-io/valkey-go v1.0.54 // indirect
	golang.org/x/crypto v0.8.0 // indirect
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gorm.io/driver/sqlite v1.5.7 // indirect
)
