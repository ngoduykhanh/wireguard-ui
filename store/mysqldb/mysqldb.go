// Package mysqldb provides a MySQL storage backend for Wireguard UI
package mysqldb

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/go-sql-driver/mysql"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// MySQLDB - Representation of MySQL database backend
type MySQLDB struct {
	conn   *sql.DB
	schema string
	dbName string
}

// String to split each item in array
var arrayDelimiter = ","

// New returns pointer to MySQL database
func New(uname string, pwd string, host string, port int, database string, tls string, templateBox *rice.Box) (*MySQLDB, error) {
	// Set connection config
	config := mysql.NewConfig()
	config.User = uname
	config.Passwd = pwd
	config.Net = "tcp"
	config.Addr = fmt.Sprintf("%s:%d", host, port)
	config.DBName = database
	config.MultiStatements = true
	config.ParseTime = true
	config.TLSConfig = tls

	// Open connection pool
	conn, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		return nil, err
	}
	conn.SetConnMaxLifetime(time.Minute * 3)
	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(10)

	// Test the connection
	if err := conn.Ping(); err != nil {
		return nil, err
	}

	// Load DB schema
	schema, err := templateBox.String("mysql.sql")
	if err != nil {
		return nil, err
	}

	ans := MySQLDB{
		conn:   conn,
		schema: schema,
		dbName: database,
	}
	return &ans, nil
}

// Init initializes the database
func (o *MySQLDB) Init() error {
	// Check if database is empty
	var databaseEmpty int
	err := o.conn.QueryRow(
		"SELECT COUNT(DISTINCT `table_name`) FROM `information_schema`.`columns` WHERE `table_schema` = ?",
		o.dbName,
	).Scan(&databaseEmpty)
	if err != nil {
		return err
	}

	if !(databaseEmpty > 0) {
		// Initialize database
		// Tell the user what we're doing as this could take a while
		fmt.Println("Initializing database")

		// Create database schema
		if _, err := o.conn.Exec(o.schema); err != nil {
			return err
		}

		// servers's interface
		if _, err := o.conn.Exec(
			"INSERT INTO interfaces (addresses, listen_port, updated_at) VALUES (?, ?, ?);",
			util.DefaultServerAddress,
			util.DefaultServerPort,
			time.Now().UTC(),
		); err != nil {
			return err
		}

		// server's keypair
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}

		if _, err := o.conn.Exec(
			"INSERT INTO keypair (private_key, public_key, updated_at) VALUES (?, ?, ?);",
			key.String(),
			key.PublicKey().String(),
			time.Now().UTC(),
		); err != nil {
			return err
		}

		// global settings
		publicInterface, err := util.GetPublicIP()
		if err != nil {
			return err
		}

		if _, err := o.conn.Exec(
			"INSERT INTO global_settings (endpoint_address, dns_servers, mtu, persistent_keepalive, config_file_path, updated_at) VALUES (?, ?, ?, ?, ?, ?);",
			publicInterface.IPAddress,
			util.DefaultDNS,
			util.DefaultMTU,
			util.DefaultPersistentKeepalive,
			util.DefaultConfigFilePath,
			time.Now().UTC(),
		); err != nil {
			return err
		}

		// user info
		if _, err := o.conn.Exec(
			"INSERT INTO users (username, password) VALUES (?, ?);",
			util.GetCredVar(util.UsernameEnvVar, util.DefaultUsername),
			util.GetCredVar(util.PasswordEnvVar, util.DefaultPassword),
		); err != nil {
			return err
		}
	}

	return nil
}

// GetUser func to query user info from the database
func (o *MySQLDB) GetUser() (model.User, error) {
	user := model.User{}
	row := o.conn.QueryRow("SELECT username, password FROM users;")
	err := row.Scan(
		&user.Username,
		&user.Password,
	)
	return user, err
}

// GetGlobalSettings func to query global settings from the database
func (o *MySQLDB) GetGlobalSettings() (model.GlobalSetting, error) {
	settings := model.GlobalSetting{}
	var dnsServers string

	row := o.conn.QueryRow("SELECT endpoint_address, dns_servers, mtu, persistent_keepalive, config_file_path, updated_at FROM global_settings;")
	// Can't use ScanStruct here as doesn't know how to handle
	// dns_servers list. Instead we must populate struct it manually.
	err := row.Scan(
		&settings.EndpointAddress,
		&dnsServers,
		&settings.MTU,
		&settings.PersistentKeepalive,
		&settings.ConfigFilePath,
		&settings.UpdatedAt,
	)
	settings.DNSServers = strings.Split(dnsServers, arrayDelimiter)
	return settings, err
}

// GetServer func to query Server setting from the database
func (o *MySQLDB) GetServer() (model.Server, error) {
	server := model.Server{}

	// Get interface
	serverInterface := model.ServerInterface{}
	var addresses string

	row := o.conn.QueryRow("SELECT addresses, listen_port, updated_at, post_up, post_down FROM interfaces;")
	err := row.Scan(
		&addresses,
		&serverInterface.ListenPort,
		&serverInterface.UpdatedAt,
		&serverInterface.PostUp,
		&serverInterface.PostDown,
	)
	serverInterface.Addresses = strings.Split(addresses, arrayDelimiter)
	if err != nil {
		return server, err
	}

	// Get keypair
	serverKeyPair := model.ServerKeypair{}
	if err := o.conn.QueryRow("SELECT private_key, public_key, updated_at FROM keypair;").
		Scan(
			&serverKeyPair.PrivateKey,
			&serverKeyPair.PublicKey,
			&serverKeyPair.UpdatedAt,
		); err != nil {
		return server, err
	}

	// create Server object and return
	server.Interface = &serverInterface
	server.KeyPair = &serverKeyPair
	return server, nil
}

// GetClients func to query Client settings from the database
func (o *MySQLDB) GetClients(hasQRCode bool) ([]model.ClientData, error) {
	var clients []model.ClientData

	rows, err := o.conn.Query("SELECT * FROM clients;")
	if err != nil {
		return clients, err
	}

	for rows.Next() {
		client := model.Client{}
		clientData := model.ClientData{}
		var allocatedIPs string
		var allowedIPs string
		var extraAllowedIPs string

		// Get client info
		if err := rows.Scan(
			&client.ID,
			&client.PrivateKey,
			&client.PublicKey,
			&client.PresharedKey,
			&client.Name,
			&client.Email,
			&allocatedIPs,
			&allowedIPs,
			&extraAllowedIPs,
			&client.UseServerDNS,
			&client.Enabled,
			&client.CreatedAt,
			&client.UpdatedAt,
		); err != nil {
			return clients, err
		}
		client.AllocatedIPs = strings.Split(allocatedIPs, arrayDelimiter)
		client.AllowedIPs = strings.Split(allowedIPs, arrayDelimiter)
		client.ExtraAllowedIPs = strings.Split(extraAllowedIPs, arrayDelimiter)

		// generate client qrcode image in base64
		if hasQRCode && client.PrivateKey != "" {
			server, _ := o.GetServer()
			globalSettings, _ := o.GetGlobalSettings()

			png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
			if err == nil {
				clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
			} else {
				fmt.Print("Cannot generate QR code: ", err)
			}
		}

		// create the list of clients and their qrcode data
		clientData.Client = &client
		clients = append(clients, clientData)
	}

	return clients, nil
}

// GetClientByID func to query Clients by ID from the database
func (o *MySQLDB) GetClientByID(clientID string, hasQRCode bool) (model.ClientData, error) {
	client := model.Client{}
	clientData := model.ClientData{}
	var allocatedIPs string
	var allowedIPs string
	var extraAllowedIPs string

	// read client info
	if err := o.conn.QueryRow("SELECT * FROM clients WHERE id = ?;", clientID).Scan(
		&client.ID,
		&client.PrivateKey,
		&client.PublicKey,
		&client.PresharedKey,
		&client.Name,
		&client.Email,
		&allocatedIPs,
		&allowedIPs,
		&extraAllowedIPs,
		&client.UseServerDNS,
		&client.Enabled,
		&client.CreatedAt,
		&client.UpdatedAt,
	); err != nil {
		return clientData, err
	}
	client.AllocatedIPs = strings.Split(allocatedIPs, arrayDelimiter)
	client.AllowedIPs = strings.Split(allowedIPs, arrayDelimiter)
	client.ExtraAllowedIPs = strings.Split(extraAllowedIPs, arrayDelimiter)

	// generate client qrcode image in base64
	if hasQRCode && client.PrivateKey != "" {
		server, _ := o.GetServer()
		globalSettings, _ := o.GetGlobalSettings()

		png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
		if err == nil {
			clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
		} else {
			fmt.Print("Cannot generate QR code: ", err)
		}
	}

	clientData.Client = &client

	return clientData, nil
}

// SaveClient func saves client to database
func (o *MySQLDB) SaveClient(client model.Client) error {
	// If client doesn't exist, create a record, else update existing record
	querySet := `
		SET
			@id = ?,
			@private_key = ?,
			@public_key = ?,
			@preshared_key = ?,
			@name = ?,
			@email = ?,
			@allocated_ips = ?,
			@allowed_ips = ?,
			@extra_allowed_ips = ?,
			@use_server_dns = ?,
			@enabled = ?,
			@created_at = ?,
			@updated_at = ?;`
	queryInsert := `
		INSERT INTO clients(
			id,
			private_key,
			public_key,
			preshared_key,
			NAME,
			email,
			allocated_ips,
			allowed_ips,
			extra_allowed_ips,
			use_server_dns,
			enabled,
			created_at,
			updated_at
		)
		VALUES(
			@id,
			@private_key,
			@public_key,
			@preshared_key,
			@name,
			@email,
			@allocated_ips,
			@allowed_ips,
			@extra_allowed_ips,
			@use_server_dns,
			@enabled,
			@created_at,
			@updated_at
		)
		ON DUPLICATE KEY
		UPDATE
			id = @id,
			private_key = @private_key,
			public_key = @public_key,
			preshared_key = @preshared_key,
			NAME = @name,
			email = @email,
			allocated_ips = @allocated_ips,
			allowed_ips = @allowed_ips,
			extra_allowed_ips = @extra_allowed_ips,
			use_server_dns = @use_server_dns,
			enabled = @enabled,
			created_at = @created_at,
			updated_at = @updated_at;`

	tx, err := o.conn.Begin()
	if err != nil {
		return err
	}
	// set values
	if _, err := tx.Exec(
		querySet,
		client.ID,
		client.PrivateKey,
		client.PublicKey,
		client.PresharedKey,
		client.Name,
		client.Email,
		strings.Join(client.AllocatedIPs, arrayDelimiter),
		strings.Join(client.AllowedIPs, arrayDelimiter),
		strings.Join(client.ExtraAllowedIPs, arrayDelimiter),
		client.UseServerDNS,
		client.Enabled,
		client.CreatedAt,
		client.UpdatedAt,
	); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx err: %v, rb err: %v", err, rbErr)
		}

		return err
	}

	// insert or update row
	if _, err := tx.Exec(queryInsert); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx err: %v, rb err: %v", err, rbErr)
		}

		return err
	}

	return tx.Commit()
}

// DeleteClient func deletes client from the database
func (o *MySQLDB) DeleteClient(clientID string) error {
	if _, err := o.conn.Exec("DELETE FROM clients WHERE id=?;", clientID); err != nil {
		return err
	}

	return nil
}

// SaveServerInterface func saves a server interface to database
func (o *MySQLDB) SaveServerInterface(serverInterface model.ServerInterface) error {
	// No need for ON DUPLICATE KEY UPDATE as only ever 1 record
	query := `
		UPDATE
			interfaces
		SET
			addresses = ?,
			listen_port = ?,
			updated_at = ?,
			post_up = ?,
			post_down = ?
		WHERE
			id = 1;`

	_, err := o.conn.Exec(
		query,
		strings.Join(serverInterface.Addresses, arrayDelimiter),
		serverInterface.ListenPort,
		serverInterface.UpdatedAt,
		serverInterface.PostUp,
		serverInterface.PostDown,
	)

	return err
}

// SaveServerKeyPair func saves a server keypair to database
func (o *MySQLDB) SaveServerKeyPair(serverKeyPair model.ServerKeypair) error {
	query := `
		UPDATE
			keypair
		SET
			private_key = ?,
			public_key = ?,
			updated_at = ?
		WHERE
			id = 1;`

	_, err := o.conn.Exec(
		query,
		serverKeyPair.PrivateKey,
		serverKeyPair.PublicKey,
		serverKeyPair.UpdatedAt,
	)

	return err
}

// SaveGlobalSettings saves global settings to database
func (o *MySQLDB) SaveGlobalSettings(globalSettings model.GlobalSetting) error {
	query := `
		UPDATE
			global_settings
		SET
			endpoint_address = ?,
			dns_servers = ?,
			mtu = ?,
			persistent_keepalive = ?,
			config_file_path = ?,
			updated_at = ?
		WHERE
			id = 1;`

	_, err := o.conn.Exec(
		query,
		globalSettings.EndpointAddress,
		strings.Join(globalSettings.DNSServers, arrayDelimiter),
		globalSettings.MTU,
		globalSettings.PersistentKeepalive,
		globalSettings.ConfigFilePath,
		globalSettings.UpdatedAt,
	)

	return err
}
