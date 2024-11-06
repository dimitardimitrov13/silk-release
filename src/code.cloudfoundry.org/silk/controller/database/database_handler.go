package database

import (
	"database/sql"
	"errors"
	"fmt"

	"code.cloudfoundry.org/silk/controller"
	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
)

const postgresTimeNow = "EXTRACT(EPOCH FROM now())::numeric::integer"
const mysqlTimeNow = "UNIX_TIMESTAMP()"
const MySQL = "mysql"
const Postgres = "postgres"

var RecordNotAffectedError = errors.New("record not affected")

//go:generate counterfeiter -o fakes/db.go --fake-name Db . Db
type Db interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Rebind(query string) string
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	DriverName() string
	RawConnection() *sqlx.DB
}

//go:generate counterfeiter -o fakes/migrateAdapter.go --fake-name MigrateAdapter . migrateAdapter
type migrateAdapter interface {
	Exec(db Db, dialect string, m migrate.MigrationSource, dir migrate.MigrationDirection) (int, error)
}

type DatabaseHandler struct {
	migrator   migrateAdapter
	migrations *migrate.MemoryMigrationSource
	db         Db
}

func NewDatabaseHandler(migrator migrateAdapter, db Db) *DatabaseHandler {
	return &DatabaseHandler{
		migrator: migrator,
		migrations: &migrate.MemoryMigrationSource{
			Migrations: []*migrate.Migration{
				{
					Id:   "1",
					Up:   []string{createSubnetTable(db.DriverName())},
					Down: []string{"DROP TABLE subnets"},
				},
				{
					Id:   "2",
					Up:   []string{createSubnetIPv6Table(db.DriverName())},
					Down: []string{"DROP TABLE subnets6"},
				},
			},
		},
		db: db,
	}
}

func (d *DatabaseHandler) CheckDatabase() error {
	var result int
	return d.db.QueryRow("SELECT 1").Scan(&result)
}

func (d *DatabaseHandler) All(ipv6 bool) ([]controller.Lease, error) {
	query := "SELECT underlay_ip, overlay_subnet, overlay_hwaddr FROM subnet"
	if ipv6 {
		query = "SELECT underlay_ip, overlay_subnet FROM subnet6"
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("selecting all subnets: %s", err)
	}

	defer rows.Close() // untested

	leases, err := rowsToLeases(rows)
	if err != nil {
		return nil, fmt.Errorf("selecting all subnets: %s", err)
	}

	return leases, nil
}

func (d *DatabaseHandler) AllSingleIPSubnets(ipv6 bool) ([]controller.Lease, error) {
	query := "SELECT underlay_ip, overlay_subnet, overlay_hwaddr FROM subnets WHERE overlay_subnet LIKE '%/32'"
	if ipv6 {
		query = "SELECT underlay_ip, overlay_subnet FROM subnets6 WHERE overlay_subnet LIKE '%/128'"
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("selecting all single ip subnets: %s", err)
	}

	defer rows.Close() // untested
	leases, err := rowsToLeases(rows)
	if err != nil {
		return nil, fmt.Errorf("selecting all single ip subnets: %s", err)
	}

	return leases, nil
}

func (d *DatabaseHandler) AllBlockSubnets(ipv6 bool) ([]controller.Lease, error) {
	// TODO DRY

	query := "SELECT underlay_ip, overlay_subnet, overlay_hwaddr FROM subnets WHERE overlay_subnet NOT LIKE '%/32'"
	if ipv6 {
		query = "SELECT underlay_ip, overlay_subnet FROM subnets6 WHERE overlay_subnet NOT LIKE '%/128'"
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("selecting all block subnets: %s", err)
	}

	defer rows.Close() // untested

	leases, err := rowsToLeases(rows)
	if err != nil {
		return nil, fmt.Errorf("selecting all block subnets: %s", err)
	}

	return leases, nil
}

func (d *DatabaseHandler) AllActive(duration int) ([]controller.Lease, error) {
	timestamp, err := timestampForDriver(d.db.DriverName())
	if err != nil {
		return nil, err
	}

	rows, err := d.db.Query(fmt.Sprintf("SELECT underlay_ip, overlay_subnet, overlay_hwaddr FROM subnets WHERE last_renewed_at + %d > %s", duration, timestamp))
	if err != nil {
		return nil, fmt.Errorf("selecting all active subnets: %s", err)
	}

	defer rows.Close() // untested

	leases, err := rowsToLeases(rows)
	if err != nil {
		return nil, fmt.Errorf("selecting all active subnets: %s", err)
	}

	rows6, err := d.db.Query(fmt.Sprintf("SELECT underlay_ip, overlay_subnet FROM subnets6 WHERE last_renewed_at + %d > %s", duration, timestamp))
	if err != nil {
		return nil, fmt.Errorf("selecting all active subnets: %s", err)
	}

	defer rows6.Close() // untested

	leases6, err := rowsToLeases(rows)
	if err != nil {
		return nil, fmt.Errorf("selecting all active subnets: %s", err)
	}

	return append(leases, leases6...), nil
}

func (d *DatabaseHandler) OldestExpiredBlockSubnet(expirationTime int, ipv6 bool) (*controller.Lease, error) {
	timestamp, err := timestampForDriver(d.db.DriverName())
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT underlay_ip, overlay_subnet, overlay_hwaddr FROM subnets WHERE overlay_subnet NOT LIKE '%%/32' AND last_renewed_at + %d <= %s ORDER BY last_renewed_at ASC LIMIT 1", expirationTime, timestamp)
	if ipv6 {
		query = fmt.Sprintf("SELECT underlay_ip, overlay_subnet FROM subnets6 WHERE overlay_subnet NOT LIKE '%%/128' AND last_renewed_at + %d <= %s ORDER BY last_renewed_at ASC LIMIT 1", expirationTime, timestamp)
	}

	var underlayIP, overlaySubnet, overlayHWAddr string

	result := d.db.QueryRow(query)

	err = result.Scan(&underlayIP, &overlaySubnet, &overlayHWAddr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan result: %s", err)
	}
	return &controller.Lease{
		UnderlayIP:          underlayIP,
		OverlaySubnet:       overlaySubnet,
		OverlayHardwareAddr: overlayHWAddr,
	}, nil
}

func (d *DatabaseHandler) OldestExpiredSingleIP(expirationTime int, ipv6 bool) (*controller.Lease, error) {
	// TODO DRY
	timestamp, err := timestampForDriver(d.db.DriverName())
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT underlay_ip, overlay_subnet, overlay_hwaddr FROM subnets WHERE overlay_subnet LIKE '%%/32' AND last_renewed_at + %d <= %s ORDER BY last_renewed_at ASC LIMIT 1", expirationTime, timestamp)
	if ipv6 {
		query = fmt.Sprintf("SELECT underlay_ip, overlay_subnet FROM subnets6 WHERE overlay_subnet LIKE '%%/128' AND last_renewed_at + %d <= %s ORDER BY last_renewed_at ASC LIMIT 1", expirationTime, timestamp)

	}
	var underlayIP, overlaySubnet, overlayHWAddr string

	result := d.db.QueryRow(query)

	err = result.Scan(&underlayIP, &overlaySubnet, &overlayHWAddr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan result: %s", err)
	}

	return &controller.Lease{
		UnderlayIP:          underlayIP,
		OverlaySubnet:       overlaySubnet,
		OverlayHardwareAddr: overlayHWAddr,
	}, nil
}

func (d *DatabaseHandler) Migrate() (int, error) {
	migrations := d.migrations
	numMigrations, err := d.migrator.Exec(d.db, d.db.DriverName(), *migrations, migrate.Up)
	if err != nil {
		return 0, fmt.Errorf("migrating: %s", err)
	}
	return numMigrations, nil
}

func (d *DatabaseHandler) AddEntry(lease controller.Lease, ipv6 bool) error {
	// Get the appropriate timestamp function for the driver
	timestamp, err := timestampForDriver(d.db.DriverName())
	if err != nil {
		return err
	}

	// Define the query based on whether the entry is for IPv6
	var query string
	if ipv6 {
		query = fmt.Sprintf("INSERT INTO subnets6 (underlay_ip, overlay_subnet, last_renewed_at) VALUES (?, ?, %s)", timestamp)
	} else {
		query = fmt.Sprintf("INSERT INTO subnets (underlay_ip, overlay_subnet, overlay_hwaddr, last_renewed_at) VALUES (?, ?, ?, %s)", timestamp)
	}

	// Rebind the query to match the driver's placeholder requirements
	query = d.db.Rebind(query)

	// Prepare the arguments for the query
	var args []interface{}
	if ipv6 {
		args = []interface{}{lease.UnderlayIP, lease.OverlaySubnet}
	} else {
		args = []interface{}{lease.UnderlayIP, lease.OverlaySubnet, lease.OverlayHardwareAddr}
	}

	// Execute the query
	_, err = d.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("adding entry: %w", err)
	}
	return nil
}

func (d *DatabaseHandler) DeleteEntry(underlayIP string, ipv6 bool) error {
	query := "DELETE FROM subnets WHERE underlay_ip = ?"
	if ipv6 {
		query = "DELETE FROM subnets6 WHERE underlay_ip = ?"
	}

	deleteRows, err := d.db.Exec(d.db.Rebind(query), underlayIP)

	if err != nil {
		return fmt.Errorf("deleting entry: %s", err)
	}

	rowsAffected, err := deleteRows.RowsAffected()
	if err != nil {
		return fmt.Errorf("parse result: %s", err)
	}

	if rowsAffected == 0 {
		return RecordNotAffectedError
	}

	return nil
}

func (d *DatabaseHandler) LeaseForUnderlayIP(underlayIP string, ipv6 bool) (*controller.Lease, error) {
	var overlaySubnet, overlayHWAddr string

	query := "SELECT overlay_subnet, overlay_hwaddr FROM subnets WHERE underlay_ip = ?"
	if ipv6 {
		query = "SELECT overlay_subnet FROM subnets WHERE underlay_ip = ?"
	}

	result := d.db.QueryRow(d.db.Rebind(query), underlayIP)

	err := result.Scan(&overlaySubnet, &overlayHWAddr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		return nil, err // test me
	}

	return &controller.Lease{
		UnderlayIP:          underlayIP,
		OverlaySubnet:       overlaySubnet,
		OverlayHardwareAddr: overlayHWAddr,
	}, nil
}

func (d *DatabaseHandler) RenewLeaseForUnderlayIP(underlayIP string, ipv6 bool) error {
	timestamp, err := timestampForDriver(d.db.DriverName())
	if err != nil {
		return err
	}

	query := fmt.Sprintf("UPDATE subnets SET last_renewed_at = %s WHERE underlay_ip = ?", timestamp)
	if ipv6 {
		query = fmt.Sprintf("UPDATE subnets6 SET last_renewed_at = %s WHERE underlay_ip = ?", timestamp)
	}

	_, err = d.db.Exec(d.db.Rebind(query), underlayIP)
	if err != nil {
		return fmt.Errorf("renewing lease: %s", err)
	}

	return nil
}

func (d *DatabaseHandler) LastRenewedAtForUnderlayIP(underlayIP string, ipv6 bool) (int64, error) {
	var lastRenewedAt int64

	query := "SELECT last_renewed_at FROM subnets WHERE underlay_ip = ?"
	if ipv6 {
		query = "SELECT last_renewed_at FROM subnets6 WHERE underlay_ip = ?"
	}

	result := d.db.QueryRow(d.db.Rebind(query), underlayIP)

	err := result.Scan(&lastRenewedAt)
	if err != nil {
		return 0, err
	}

	return lastRenewedAt, nil
}

func rowsToLeases(rows *sql.Rows) ([]controller.Lease, error) {
	leases := []controller.Lease{}

	for rows.Next() {
		var underlayIP, overlaySubnet, overlayHWAddr string

		err := rows.Scan(&underlayIP, &overlaySubnet, &overlayHWAddr)
		if err != nil {
			return nil, fmt.Errorf("parsing result: %s", err)
		}

		leases = append(leases, controller.Lease{
			UnderlayIP:          underlayIP,
			OverlaySubnet:       overlaySubnet,
			OverlayHardwareAddr: overlayHWAddr,
		})
	}

	err := rows.Err()
	if err != nil {
		return nil, fmt.Errorf("getting next row: %s", err) // untested
	}

	return leases, nil
}

func createSubnetTable(dbType string) string {
	baseCreateTable := "CREATE TABLE IF NOT EXISTS subnets (" +
		"%s" +
		", underlay_ip varchar(15) NOT NULL" +
		", overlay_subnet varchar(18) NOT NULL" +
		", overlay_hwaddr varchar(17) NOT NULL" +
		", last_renewed_at bigint NOT NULL" +
		", UNIQUE (underlay_ip)" +
		", UNIQUE (overlay_subnet)" +
		", UNIQUE (overlay_hwaddr)" +
		");"
	mysqlId := "id int NOT NULL AUTO_INCREMENT, PRIMARY KEY (id)"
	psqlId := "id SERIAL PRIMARY KEY"

	switch dbType {
	case Postgres:
		return fmt.Sprintf(baseCreateTable, psqlId)
	case MySQL:
		return fmt.Sprintf(baseCreateTable, mysqlId)
	}

	return ""
}

func timestampForDriver(driverName string) (string, error) {
	switch driverName {
	case MySQL:
		return mysqlTimeNow, nil
	case Postgres:
		return postgresTimeNow, nil
	default:
		return "", fmt.Errorf("database type %s is not supported", driverName)
	}
}

func createSubnetIPv6Table(dbType string) string {
	baseCreateTable := "CREATE TABLE IF NOT EXISTS subnets6 (" +
		"%s" +
		", underlay_ip varchar(39) NOT NULL" +
		", overlay_subnet varchar(43) NOT NULL" +
		", last_renewed_at bigint NOT NULL" +
		", UNIQUE (underlay_ip)" +
		", UNIQUE (overlay_subnet)" +
		", UNIQUE (overlay_hwaddr)" +
		");"
	mysqlId := "id int NOT NULL AUTO_INCREMENT, PRIMARY KEY (id)"
	psqlId := "id SERIAL PRIMARY KEY"

	switch dbType {
	case Postgres:
		return fmt.Sprintf(baseCreateTable, psqlId)
	case MySQL:
		return fmt.Sprintf(baseCreateTable, mysqlId)
	}

	return ""
}
