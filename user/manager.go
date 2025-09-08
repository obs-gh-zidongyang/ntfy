// Package user deals with authentication and authorization against topics
package user

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"heckel.io/ntfy/v2/log"
	"heckel.io/ntfy/v2/payments"
	"heckel.io/ntfy/v2/util"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	tierIDPrefix                    = "ti_"
	tierIDLength                    = 8
	syncTopicPrefix                 = "st_"
	syncTopicLength                 = 16
	userIDPrefix                    = "u_"
	userIDLength                    = 12
	userAuthIntentionalSlowDownHash = "$2a$10$YFCQvqQDwIIwnJM1xkAYOeih0dg17UVGanaTStnrSzC8NCWxcLDwy" // Cost should match DefaultUserPasswordBcryptCost
	userHardDeleteAfterDuration     = 7 * 24 * time.Hour
	tokenPrefix                     = "tk_"
	tokenLength                     = 32
	tokenMaxCount                   = 60 // Only keep this many tokens in the table per user
	tag                             = "user_manager"
)

// Default constants that may be overridden by configs
const (
	DefaultUserStatsQueueWriterInterval = 33 * time.Second
	DefaultUserPasswordBcryptCost       = 10
)

var (
	errNoTokenProvided    = errors.New("no token provided")
	errTopicOwnedByOthers = errors.New("topic owned by others")
	errNoRows             = errors.New("no rows found")
)

// Manager-related queries
const (
	createTablesQueries = `
		BEGIN;
		CREATE TABLE IF NOT EXISTS tier (
			id TEXT PRIMARY KEY,
			code TEXT NOT NULL,
			name TEXT NOT NULL,
			messages_limit INT NOT NULL,
			messages_expiry_duration INT NOT NULL,
			emails_limit INT NOT NULL,
			calls_limit INT NOT NULL,
			reservations_limit INT NOT NULL,
			attachment_file_size_limit INT NOT NULL,
			attachment_total_size_limit INT NOT NULL,
			attachment_expiry_duration INT NOT NULL,
			attachment_bandwidth_limit INT NOT NULL,
			stripe_monthly_price_id TEXT,
			stripe_yearly_price_id TEXT
		);
		CREATE UNIQUE INDEX idx_tier_code ON tier (code);
		CREATE UNIQUE INDEX idx_tier_stripe_monthly_price_id ON tier (stripe_monthly_price_id);
		CREATE UNIQUE INDEX idx_tier_stripe_yearly_price_id ON tier (stripe_yearly_price_id);
		CREATE TABLE IF NOT EXISTS user (
		    id TEXT PRIMARY KEY,
			tier_id TEXT,
			user TEXT NOT NULL,
			pass TEXT NOT NULL,
			role TEXT CHECK (role IN ('anonymous', 'admin', 'user')) NOT NULL,
			prefs JSON NOT NULL DEFAULT '{}',
			sync_topic TEXT NOT NULL,
			provisioned INT NOT NULL,
			stats_messages INT NOT NULL DEFAULT (0),
			stats_emails INT NOT NULL DEFAULT (0),
			stats_calls INT NOT NULL DEFAULT (0),
			stripe_customer_id TEXT,
			stripe_subscription_id TEXT,
			stripe_subscription_status TEXT,
			stripe_subscription_interval TEXT,
			stripe_subscription_paid_until INT,
			stripe_subscription_cancel_at INT,
			created INT NOT NULL,
			deleted INT,
		    FOREIGN KEY (tier_id) REFERENCES tier (id)
		);
		CREATE UNIQUE INDEX idx_user ON user (user);
		CREATE UNIQUE INDEX idx_user_stripe_customer_id ON user (stripe_customer_id);
		CREATE UNIQUE INDEX idx_user_stripe_subscription_id ON user (stripe_subscription_id);
		CREATE TABLE IF NOT EXISTS user_access (
			user_id TEXT NOT NULL,
			topic TEXT NOT NULL,
			read INT NOT NULL,
			write INT NOT NULL,
			owner_user_id INT,
			provisioned INT NOT NULL,
			PRIMARY KEY (user_id, topic),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE,
		    FOREIGN KEY (owner_user_id) REFERENCES user (id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS user_token (
			user_id TEXT NOT NULL,
			token TEXT NOT NULL,
			label TEXT NOT NULL,
			last_access INT NOT NULL,
			last_origin TEXT NOT NULL,
			expires INT NOT NULL,
			provisioned INT NOT NULL,
			PRIMARY KEY (user_id, token),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
		);
		CREATE UNIQUE INDEX idx_user_token ON user_token (token);
		CREATE TABLE IF NOT EXISTS user_phone (
			user_id TEXT NOT NULL,
			phone_number TEXT NOT NULL,
			PRIMARY KEY (user_id, phone_number),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS schemaVersion (
			id INT PRIMARY KEY,
			version INT NOT NULL
		);
		INSERT INTO user (id, user, pass, role, sync_topic, provisioned, created)
		VALUES ('` + everyoneID + `', '*', '', 'anonymous', '', false, UNIXEPOCH())
		ON CONFLICT (id) DO NOTHING;
		COMMIT;
	`

	builtinStartupQueries = `
		PRAGMA foreign_keys = ON;
	`

	selectUserByIDQuery = `
		SELECT u.id, u.user, u.pass, u.role, u.prefs, u.sync_topic, u.provisioned, u.stats_messages, u.stats_emails, u.stats_calls, u.stripe_customer_id, u.stripe_subscription_id, u.stripe_subscription_status, u.stripe_subscription_interval, u.stripe_subscription_paid_until, u.stripe_subscription_cancel_at, deleted, t.id, t.code, t.name, t.messages_limit, t.messages_expiry_duration, t.emails_limit, t.calls_limit, t.reservations_limit, t.attachment_file_size_limit, t.attachment_total_size_limit, t.attachment_expiry_duration, t.attachment_bandwidth_limit, t.stripe_monthly_price_id, t.stripe_yearly_price_id
		FROM user u
		LEFT JOIN tier t on t.id = u.tier_id
		WHERE u.id = ?
	`
	selectUserByNameQuery = `
		SELECT u.id, u.user, u.pass, u.role, u.prefs, u.sync_topic, u.provisioned, u.stats_messages, u.stats_emails, u.stats_calls, u.stripe_customer_id, u.stripe_subscription_id, u.stripe_subscription_status, u.stripe_subscription_interval, u.stripe_subscription_paid_until, u.stripe_subscription_cancel_at, deleted, t.id, t.code, t.name, t.messages_limit, t.messages_expiry_duration, t.emails_limit, t.calls_limit, t.reservations_limit, t.attachment_file_size_limit, t.attachment_total_size_limit, t.attachment_expiry_duration, t.attachment_bandwidth_limit, t.stripe_monthly_price_id, t.stripe_yearly_price_id
		FROM user u
		LEFT JOIN tier t on t.id = u.tier_id
		WHERE user = ?
	`
	selectUserByTokenQuery = `
		SELECT u.id, u.user, u.pass, u.role, u.prefs, u.sync_topic, u.provisioned, u.stats_messages, u.stats_emails, u.stats_calls, u.stripe_customer_id, u.stripe_subscription_id, u.stripe_subscription_status, u.stripe_subscription_interval, u.stripe_subscription_paid_until, u.stripe_subscription_cancel_at, deleted, t.id, t.code, t.name, t.messages_limit, t.messages_expiry_duration, t.emails_limit, t.calls_limit, t.reservations_limit, t.attachment_file_size_limit, t.attachment_total_size_limit, t.attachment_expiry_duration, t.attachment_bandwidth_limit, t.stripe_monthly_price_id, t.stripe_yearly_price_id
		FROM user u
		JOIN user_token tk on u.id = tk.user_id
		LEFT JOIN tier t on t.id = u.tier_id
		WHERE tk.token = ? AND (tk.expires = 0 OR tk.expires >= ?)
	`
	selectUserByStripeCustomerIDQuery = `
		SELECT u.id, u.user, u.pass, u.role, u.prefs, u.sync_topic, u.provisioned, u.stats_messages, u.stats_emails, u.stats_calls, u.stripe_customer_id, u.stripe_subscription_id, u.stripe_subscription_status, u.stripe_subscription_interval, u.stripe_subscription_paid_until, u.stripe_subscription_cancel_at, deleted, t.id, t.code, t.name, t.messages_limit, t.messages_expiry_duration, t.emails_limit, t.calls_limit, t.reservations_limit, t.attachment_file_size_limit, t.attachment_total_size_limit, t.attachment_expiry_duration, t.attachment_bandwidth_limit, t.stripe_monthly_price_id, t.stripe_yearly_price_id
		FROM user u
		LEFT JOIN tier t on t.id = u.tier_id
		WHERE u.stripe_customer_id = ?
	`
	selectTopicPermsQuery = `
		SELECT read, write
		FROM user_access a
		JOIN user u ON u.id = a.user_id
		WHERE (u.user = ? OR u.user = ?) AND ? LIKE a.topic ESCAPE '\'
		ORDER BY u.user DESC, LENGTH(a.topic) DESC, a.write DESC
	`

	insertUserQuery = `
		INSERT INTO user (id, user, pass, role, sync_topic, provisioned, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	selectUsernamesQuery = `
		SELECT user
		FROM user
		ORDER BY
			CASE role
				WHEN 'admin' THEN 1
				WHEN 'anonymous' THEN 3
				ELSE 2
			END, user
	`
	selectUserCountQuery          = `SELECT COUNT(*) FROM user`
	selectUserIDFromUsernameQuery = `SELECT id FROM user WHERE user = ?`
	updateUserPassQuery           = `UPDATE user SET pass = ? WHERE user = ?`
	updateUserRoleQuery           = `UPDATE user SET role = ? WHERE user = ?`
	updateUserProvisionedQuery    = `UPDATE user SET provisioned = ? WHERE user = ?`
	updateUserPrefsQuery          = `UPDATE user SET prefs = ? WHERE id = ?`
	updateUserStatsQuery          = `UPDATE user SET stats_messages = ?, stats_emails = ?, stats_calls = ? WHERE id = ?`
	updateUserStatsResetAllQuery  = `UPDATE user SET stats_messages = 0, stats_emails = 0, stats_calls = 0`
	updateUserDeletedQuery        = `UPDATE user SET deleted = ? WHERE id = ?`
	deleteUsersMarkedQuery        = `DELETE FROM user WHERE deleted < ?`
	deleteUserQuery               = `DELETE FROM user WHERE user = ?`

	upsertUserAccessQuery = `
		INSERT INTO user_access (user_id, topic, read, write, owner_user_id, provisioned)
		VALUES ((SELECT id FROM user WHERE user = ?), ?, ?, ?, (SELECT IIF(?='',NULL,(SELECT id FROM user WHERE user=?))), ?)
		ON CONFLICT (user_id, topic)
		DO UPDATE SET read=excluded.read, write=excluded.write, owner_user_id=excluded.owner_user_id, provisioned=excluded.provisioned
	`
	selectUserAllAccessQuery = `
		SELECT user_id, topic, read, write, provisioned
		FROM user_access
		ORDER BY LENGTH(topic) DESC, write DESC, read DESC, topic
	`
	selectUserAccessQuery = `
		SELECT topic, read, write, provisioned
		FROM user_access
		WHERE user_id = (SELECT id FROM user WHERE user = ?)
		ORDER BY LENGTH(topic) DESC, write DESC, read DESC, topic
	`
	selectUserReservationsQuery = `
		SELECT a_user.topic, a_user.read, a_user.write, a_everyone.read AS everyone_read, a_everyone.write AS everyone_write
		FROM user_access a_user
		LEFT JOIN  user_access a_everyone ON a_user.topic = a_everyone.topic AND a_everyone.user_id = (SELECT id FROM user WHERE user = ?)
		WHERE a_user.user_id = a_user.owner_user_id
		  AND a_user.owner_user_id = (SELECT id FROM user WHERE user = ?)
		ORDER BY a_user.topic
	`
	selectUserReservationsCountQuery = `
		SELECT COUNT(*)
		FROM user_access
		WHERE user_id = owner_user_id
		  AND owner_user_id = (SELECT id FROM user WHERE user = ?)
	`
	selectUserReservationsOwnerQuery = `
		SELECT owner_user_id
		FROM user_access
		WHERE topic = ?
		  AND user_id = owner_user_id
	`
	selectUserHasReservationQuery = `
		SELECT COUNT(*)
		FROM user_access
		WHERE user_id = owner_user_id
		  AND owner_user_id = (SELECT id FROM user WHERE user = ?)
		  AND topic = ?
	`
	selectOtherAccessCountQuery = `
		SELECT COUNT(*)
		FROM user_access
		WHERE (topic = ? OR ? LIKE topic ESCAPE '\')
		  AND (owner_user_id IS NULL OR owner_user_id != (SELECT id FROM user WHERE user = ?))
	`
	deleteAllAccessQuery  = `DELETE FROM user_access`
	deleteUserAccessQuery = `
		DELETE FROM user_access
		WHERE user_id = (SELECT id FROM user WHERE user = ?)
		   OR owner_user_id = (SELECT id FROM user WHERE user = ?)
	`
	deleteUserAccessProvisionedQuery = `DELETE FROM user_access WHERE provisioned = 1`
	deleteTopicAccessQuery           = `
		DELETE FROM user_access
	   	WHERE (user_id = (SELECT id FROM user WHERE user = ?) OR owner_user_id = (SELECT id FROM user WHERE user = ?))
	   	  AND topic = ?
  	`

	selectTokenCountQuery           = `SELECT COUNT(*) FROM user_token WHERE user_id = ?`
	selectTokensQuery               = `SELECT token, label, last_access, last_origin, expires, provisioned FROM user_token WHERE user_id = ?`
	selectTokenQuery                = `SELECT token, label, last_access, last_origin, expires, provisioned FROM user_token WHERE user_id = ? AND token = ?`
	selectAllProvisionedTokensQuery = `SELECT token, label, last_access, last_origin, expires, provisioned FROM user_token WHERE provisioned = 1`
	upsertTokenQuery                = `
		INSERT INTO user_token (user_id, token, label, last_access, last_origin, expires, provisioned)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, token)
		DO UPDATE SET label = excluded.label, expires = excluded.expires, provisioned = excluded.provisioned;
	`
	updateTokenExpiryQuery      = `UPDATE user_token SET expires = ? WHERE user_id = ? AND token = ?`
	updateTokenLabelQuery       = `UPDATE user_token SET label = ? WHERE user_id = ? AND token = ?`
	updateTokenLastAccessQuery  = `UPDATE user_token SET last_access = ?, last_origin = ? WHERE token = ?`
	deleteTokenQuery            = `DELETE FROM user_token WHERE user_id = ? AND token = ?`
	deleteProvisionedTokenQuery = `DELETE FROM user_token WHERE token = ?`
	deleteAllTokenQuery         = `DELETE FROM user_token WHERE user_id = ?`
	deleteExpiredTokensQuery    = `DELETE FROM user_token WHERE expires > 0 AND expires < ?`
	deleteExcessTokensQuery     = `
		DELETE FROM user_token
		WHERE user_id = ?
		  AND (user_id, token) NOT IN (
			SELECT user_id, token
			FROM user_token
			WHERE user_id = ?
			ORDER BY expires DESC
			LIMIT ?
		)
	`

	selectPhoneNumbersQuery = `SELECT phone_number FROM user_phone WHERE user_id = ?`
	insertPhoneNumberQuery  = `INSERT INTO user_phone (user_id, phone_number) VALUES (?, ?)`
	deletePhoneNumberQuery  = `DELETE FROM user_phone WHERE user_id = ? AND phone_number = ?`

	insertTierQuery = `
		INSERT INTO tier (id, code, name, messages_limit, messages_expiry_duration, emails_limit, calls_limit, reservations_limit, attachment_file_size_limit, attachment_total_size_limit, attachment_expiry_duration, attachment_bandwidth_limit, stripe_monthly_price_id, stripe_yearly_price_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	updateTierQuery = `
		UPDATE tier
		SET name = ?, messages_limit = ?, messages_expiry_duration = ?, emails_limit = ?, calls_limit = ?, reservations_limit = ?, attachment_file_size_limit = ?, attachment_total_size_limit = ?, attachment_expiry_duration = ?, attachment_bandwidth_limit = ?, stripe_monthly_price_id = ?, stripe_yearly_price_id = ?
		WHERE code = ?
	`
	selectTiersQuery = `
		SELECT id, code, name, messages_limit, messages_expiry_duration, emails_limit, calls_limit, reservations_limit, attachment_file_size_limit, attachment_total_size_limit, attachment_expiry_duration, attachment_bandwidth_limit, stripe_monthly_price_id, stripe_yearly_price_id
		FROM tier
	`
	selectTierByCodeQuery = `
		SELECT id, code, name, messages_limit, messages_expiry_duration, emails_limit, calls_limit, reservations_limit, attachment_file_size_limit, attachment_total_size_limit, attachment_expiry_duration, attachment_bandwidth_limit, stripe_monthly_price_id, stripe_yearly_price_id
		FROM tier
		WHERE code = ?
	`
	selectTierByPriceIDQuery = `
		SELECT id, code, name, messages_limit, messages_expiry_duration, emails_limit, calls_limit, reservations_limit, attachment_file_size_limit, attachment_total_size_limit, attachment_expiry_duration, attachment_bandwidth_limit, stripe_monthly_price_id, stripe_yearly_price_id
		FROM tier
		WHERE (stripe_monthly_price_id = ? OR stripe_yearly_price_id = ?)
	`
	updateUserTierQuery = `UPDATE user SET tier_id = (SELECT id FROM tier WHERE code = ?) WHERE user = ?`
	deleteUserTierQuery = `UPDATE user SET tier_id = null WHERE user = ?`
	deleteTierQuery     = `DELETE FROM tier WHERE code = ?`

	updateBillingQuery = `
		UPDATE user
		SET stripe_customer_id = ?, stripe_subscription_id = ?, stripe_subscription_status = ?, stripe_subscription_interval = ?, stripe_subscription_paid_until = ?, stripe_subscription_cancel_at = ?
		WHERE user = ?
	`
)

// Schema management queries
const (
	currentSchemaVersion     = 6
	insertSchemaVersion      = `INSERT INTO schemaVersion VALUES (1, ?)`
	updateSchemaVersion      = `UPDATE schemaVersion SET version = ? WHERE id = 1`
	selectSchemaVersionQuery = `SELECT version FROM schemaVersion WHERE id = 1`

	// 1 -> 2 (complex migration!)
	migrate1To2CreateTablesQueries = `
		ALTER TABLE user RENAME TO user_old;
		CREATE TABLE IF NOT EXISTS tier (
			id TEXT PRIMARY KEY,
			code TEXT NOT NULL,
			name TEXT NOT NULL,
			messages_limit INT NOT NULL,
			messages_expiry_duration INT NOT NULL,
			emails_limit INT NOT NULL,
			reservations_limit INT NOT NULL,
			attachment_file_size_limit INT NOT NULL,
			attachment_total_size_limit INT NOT NULL,
			attachment_expiry_duration INT NOT NULL,
			attachment_bandwidth_limit INT NOT NULL,
			stripe_price_id TEXT
		);
		CREATE UNIQUE INDEX idx_tier_code ON tier (code);
		CREATE UNIQUE INDEX idx_tier_price_id ON tier (stripe_price_id);
		CREATE TABLE IF NOT EXISTS user (
		    id TEXT PRIMARY KEY,
			tier_id TEXT,
			user TEXT NOT NULL,
			pass TEXT NOT NULL,
			role TEXT CHECK (role IN ('anonymous', 'admin', 'user')) NOT NULL,
			prefs JSON NOT NULL DEFAULT '{}',
			sync_topic TEXT NOT NULL,
			stats_messages INT NOT NULL DEFAULT (0),
			stats_emails INT NOT NULL DEFAULT (0),
			stripe_customer_id TEXT,
			stripe_subscription_id TEXT,
			stripe_subscription_status TEXT,
			stripe_subscription_paid_until INT,
			stripe_subscription_cancel_at INT,
			created INT NOT NULL,
			deleted INT,
		    FOREIGN KEY (tier_id) REFERENCES tier (id)
		);
		CREATE UNIQUE INDEX idx_user ON user (user);
		CREATE UNIQUE INDEX idx_user_stripe_customer_id ON user (stripe_customer_id);
		CREATE UNIQUE INDEX idx_user_stripe_subscription_id ON user (stripe_subscription_id);
		CREATE TABLE IF NOT EXISTS user_access (
			user_id TEXT NOT NULL,
			topic TEXT NOT NULL,
			read INT NOT NULL,
			write INT NOT NULL,
			owner_user_id INT,
			PRIMARY KEY (user_id, topic),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE,
		    FOREIGN KEY (owner_user_id) REFERENCES user (id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS user_token (
			user_id TEXT NOT NULL,
			token TEXT NOT NULL,
			label TEXT NOT NULL,
			last_access INT NOT NULL,
			last_origin TEXT NOT NULL,
			expires INT NOT NULL,
			PRIMARY KEY (user_id, token),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS schemaVersion (
			id INT PRIMARY KEY,
			version INT NOT NULL
		);
		INSERT INTO user (id, user, pass, role, sync_topic, created)
		VALUES ('u_everyone', '*', '', 'anonymous', '', UNIXEPOCH())
		ON CONFLICT (id) DO NOTHING;
	`
	migrate1To2SelectAllOldUsernamesNoTx = `SELECT user FROM user_old`
	migrate1To2InsertUserNoTx            = `
		INSERT INTO user (id, user, pass, role, sync_topic, created)
		SELECT ?, user, pass, role, ?, UNIXEPOCH() FROM user_old WHERE user = ?
	`
	migrate1To2InsertFromOldTablesAndDropNoTx = `
		INSERT INTO user_access (user_id, topic, read, write)
		SELECT u.id, a.topic, a.read, a.write
		FROM user u
	 	JOIN access a ON u.user = a.user;

		DROP TABLE access;
		DROP TABLE user_old;
	`

	// 2 -> 3
	migrate2To3UpdateQueries = `
		ALTER TABLE user ADD COLUMN stripe_subscription_interval TEXT;
		ALTER TABLE tier RENAME COLUMN stripe_price_id TO stripe_monthly_price_id;
		ALTER TABLE tier ADD COLUMN stripe_yearly_price_id TEXT;
		DROP INDEX IF EXISTS idx_tier_price_id;
		CREATE UNIQUE INDEX idx_tier_stripe_monthly_price_id ON tier (stripe_monthly_price_id);
		CREATE UNIQUE INDEX idx_tier_stripe_yearly_price_id ON tier (stripe_yearly_price_id);
	`

	// 3 -> 4
	migrate3To4UpdateQueries = `
		ALTER TABLE tier ADD COLUMN calls_limit INT NOT NULL DEFAULT (0);
		ALTER TABLE user ADD COLUMN stats_calls INT NOT NULL DEFAULT (0);
		CREATE TABLE IF NOT EXISTS user_phone (
			user_id TEXT NOT NULL,
			phone_number TEXT NOT NULL,
			PRIMARY KEY (user_id, phone_number),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
		);
	`

	// 4 -> 5
	migrate4To5UpdateQueries = `
		UPDATE user_access SET topic = REPLACE(topic, '_', '\_');
	`

	// 5 -> 6
	migrate5To6UpdateQueries = `
		PRAGMA foreign_keys=off;

		-- Alter user table: Add provisioned column
		ALTER TABLE user RENAME TO user_old;
		CREATE TABLE IF NOT EXISTS user (
		    id TEXT PRIMARY KEY,
			tier_id TEXT,
			user TEXT NOT NULL,
			pass TEXT NOT NULL,
			role TEXT CHECK (role IN ('anonymous', 'admin', 'user')) NOT NULL,
			prefs JSON NOT NULL DEFAULT '{}',
			sync_topic TEXT NOT NULL,
			provisioned INT NOT NULL,
			stats_messages INT NOT NULL DEFAULT (0),
			stats_emails INT NOT NULL DEFAULT (0),
			stats_calls INT NOT NULL DEFAULT (0),
			stripe_customer_id TEXT,
			stripe_subscription_id TEXT,
			stripe_subscription_status TEXT,
			stripe_subscription_interval TEXT,
			stripe_subscription_paid_until INT,
			stripe_subscription_cancel_at INT,
			created INT NOT NULL,
			deleted INT,
		    FOREIGN KEY (tier_id) REFERENCES tier (id)
		);
		INSERT INTO user
		SELECT
		    id,
		    tier_id,
		    user,
		    pass,
		    role,
		    prefs,
		    sync_topic,
		    0, -- provisioned
		    stats_messages,
		    stats_emails,
		    stats_calls,
		    stripe_customer_id,
		    stripe_subscription_id,
		    stripe_subscription_status,
		    stripe_subscription_interval,
		    stripe_subscription_paid_until,
		    stripe_subscription_cancel_at,
		    created,
		    deleted
		FROM user_old;
		DROP TABLE user_old;

		-- Alter user_access table: Add provisioned column
		ALTER TABLE user_access RENAME TO user_access_old;
		CREATE TABLE user_access (
			user_id TEXT NOT NULL,
			topic TEXT NOT NULL,
			read INT NOT NULL,
			write INT NOT NULL,
			owner_user_id INT,
			provisioned INTEGER NOT NULL,
			PRIMARY KEY (user_id, topic),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE,
			FOREIGN KEY (owner_user_id) REFERENCES user (id) ON DELETE CASCADE
		);
		INSERT INTO user_access SELECT *, 0 FROM user_access_old;
		DROP TABLE user_access_old;

		-- Alter user_token table: Add provisioned column
		ALTER TABLE user_token RENAME TO user_token_old;
		CREATE TABLE IF NOT EXISTS user_token (
			user_id TEXT NOT NULL,
			token TEXT NOT NULL,
			label TEXT NOT NULL,
			last_access INT NOT NULL,
			last_origin TEXT NOT NULL,
			expires INT NOT NULL,
			provisioned INT NOT NULL,
			PRIMARY KEY (user_id, token),
			FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
		);
		INSERT INTO user_token SELECT *, 0 FROM user_token_old;
		DROP TABLE user_token_old;

		-- Recreate indices
		CREATE UNIQUE INDEX idx_user ON user (user);
		CREATE UNIQUE INDEX idx_user_stripe_customer_id ON user (stripe_customer_id);
		CREATE UNIQUE INDEX idx_user_stripe_subscription_id ON user (stripe_subscription_id);
		CREATE UNIQUE INDEX idx_user_token ON user_token (token);

		-- Re-enable foreign keys
		PRAGMA foreign_keys=on;
	`
)

var (
	migrations = map[int]func(db *sql.DB) error{
		1: migrateFrom1,
		2: migrateFrom2,
		3: migrateFrom3,
		4: migrateFrom4,
		5: migrateFrom5,
	}
)

// Manager is an implementation of Manager. It stores users and access control list
// in a SQLite database.
type Manager struct {
	config     *Config
	db         *sql.DB
	statsQueue map[string]*Stats       // "Queue" to asynchronously write user stats to the database (UserID -> Stats)
	tokenQueue map[string]*TokenUpdate // "Queue" to asynchronously write token access stats to the database (Token ID -> TokenUpdate)
	mu         sync.Mutex
}

// Config holds the configuration for the user Manager
type Config struct {
	Filename            string              // Database filename, e.g. "/var/lib/ntfy/user.db"
	StartupQueries      string              // Queries to run on startup, e.g. to create initial users or tiers
	DefaultAccess       Permission          // Default permission if no ACL matches
	ProvisionEnabled    bool                // Hack: Enable auto-provisioning of users and access grants, disabled for "ntfy user" commands
	Users               []*User             // Predefined users to create on startup
	Access              map[string][]*Grant // Predefined access grants to create on startup (username -> []*Grant)
	Tokens              map[string][]*Token // Predefined users to create on startup (username -> []*Token)
	QueueWriterInterval time.Duration       // Interval for the async queue writer to flush stats and token updates to the database
	BcryptCost          int                 // Cost of generated passwords; lowering makes testing faster
}

var _ Auther = (*Manager)(nil)

// NewManager creates a new Manager instance
func NewManager(config *Config) (*Manager, error) {
	// Set defaults
	if config.BcryptCost <= 0 {
		config.BcryptCost = DefaultUserPasswordBcryptCost
	}
	if config.QueueWriterInterval.Seconds() <= 0 {
		config.QueueWriterInterval = DefaultUserStatsQueueWriterInterval
	}
	// Check the parent directory of the database file (makes for friendly error messages)
	parentDir := filepath.Dir(config.Filename)
	if !util.FileExists(parentDir) {
		return nil, fmt.Errorf("user database directory %s does not exist or is not accessible", parentDir)
	}
	// Open DB with OpenTelemetry instrumentation and run setup queries
	db, err := util.OpenInstrumentedDB("sqlite3", config.Filename)
	if err != nil {
		return nil, err
	}
	if err := setupDB(db); err != nil {
		return nil, err
	}
	if err := runStartupQueries(db, config.StartupQueries); err != nil {
		return nil, err
	}
	manager := &Manager{
		db:         db,
		config:     config,
		statsQueue: make(map[string]*Stats),
		tokenQueue: make(map[string]*TokenUpdate),
	}
	if err := manager.maybeProvisionUsersAccessAndTokens(); err != nil {
		return nil, err
	}
	go manager.asyncQueueWriter(config.QueueWriterInterval)
	return manager, nil
}

// Authenticate checks username and password and returns a User if correct, and the user has not been
// marked as deleted. The method returns in constant-ish time, regardless of whether the user exists or
// the password is correct or incorrect.
func (a *Manager) Authenticate(username, password string) (*User, error) {
	if username == Everyone {
		return nil, ErrUnauthenticated
	}
	user, err := a.User(username)
	if err != nil {
		log.Tag(tag).Field("user_name", username).Err(err).Trace("Authentication of user failed (1)")
		bcrypt.CompareHashAndPassword([]byte(userAuthIntentionalSlowDownHash), []byte("intentional slow-down to avoid timing attacks"))
		return nil, ErrUnauthenticated
	} else if user.Deleted {
		log.Tag(tag).Field("user_name", username).Trace("Authentication of user failed (2): user marked deleted")
		bcrypt.CompareHashAndPassword([]byte(userAuthIntentionalSlowDownHash), []byte("intentional slow-down to avoid timing attacks"))
		return nil, ErrUnauthenticated
	} else if err := bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(password)); err != nil {
		log.Tag(tag).Field("user_name", username).Err(err).Trace("Authentication of user failed (3)")
		return nil, ErrUnauthenticated
	}
	return user, nil
}

// AuthenticateToken checks if the token exists and returns the associated User if it does.
// The method sets the User.Token value to the token that was used for authentication.
func (a *Manager) AuthenticateToken(token string) (*User, error) {
	if len(token) != tokenLength {
		return nil, ErrUnauthenticated
	}
	user, err := a.userByToken(token)
	if err != nil {
		log.Tag(tag).Field("token", token).Err(err).Trace("Authentication of token failed")
		return nil, ErrUnauthenticated
	}
	user.Token = token
	return user, nil
}

// CreateToken generates a random token for the given user and returns it. The token expires
// after a fixed duration unless ChangeToken is called. This function also prunes tokens for the
// given user, if there are too many of them.
func (a *Manager) CreateToken(userID, label string, expires time.Time, origin netip.Addr, provisioned bool) (*Token, error) {
	return queryTx(a.db, func(tx *sql.Tx) (*Token, error) {
		return a.createTokenTx(tx, userID, GenerateToken(), label, expires, origin, provisioned)
	})
}

func (a *Manager) createTokenTx(tx *sql.Tx, userID, token, label string, expires time.Time, origin netip.Addr, provisioned bool) (*Token, error) {
	access := time.Now()
	if _, err := tx.Exec(upsertTokenQuery, userID, token, label, access.Unix(), origin.String(), expires.Unix(), provisioned); err != nil {
		return nil, err
	}
	rows, err := tx.Query(selectTokenCountQuery, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, errNoRows
	}
	var tokenCount int
	if err := rows.Scan(&tokenCount); err != nil {
		return nil, err
	}
	if tokenCount >= tokenMaxCount {
		// This pruning logic is done in two queries for efficiency. The SELECT above is a lookup
		// on two indices, whereas the query below is a full table scan.
		if _, err := tx.Exec(deleteExcessTokensQuery, userID, userID, tokenMaxCount); err != nil {
			return nil, err
		}
	}
	return &Token{
		Value:       token,
		Label:       label,
		LastAccess:  access,
		LastOrigin:  origin,
		Expires:     expires,
		Provisioned: provisioned,
	}, nil
}

// Tokens returns all existing tokens for the user with the given user ID
func (a *Manager) Tokens(userID string) ([]*Token, error) {
	rows, err := a.db.Query(selectTokensQuery, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := make([]*Token, 0)
	for {
		token, err := a.readToken(rows)
		if errors.Is(err, ErrTokenNotFound) {
			break
		} else if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (a *Manager) allProvisionedTokens() ([]*Token, error) {
	rows, err := a.db.Query(selectAllProvisionedTokensQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := make([]*Token, 0)
	for {
		token, err := a.readToken(rows)
		if errors.Is(err, ErrTokenNotFound) {
			break
		} else if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// Token returns a specific token for a user
func (a *Manager) Token(userID, token string) (*Token, error) {
	rows, err := a.db.Query(selectTokenQuery, userID, token)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return a.readToken(rows)
}

func (a *Manager) readToken(rows *sql.Rows) (*Token, error) {
	var token, label, lastOrigin string
	var lastAccess, expires int64
	var provisioned bool
	if !rows.Next() {
		return nil, ErrTokenNotFound
	}
	if err := rows.Scan(&token, &label, &lastAccess, &lastOrigin, &expires, &provisioned); err != nil {
		return nil, err
	} else if err := rows.Err(); err != nil {
		return nil, err
	}
	lastOriginIP, err := netip.ParseAddr(lastOrigin)
	if err != nil {
		lastOriginIP = netip.IPv4Unspecified()
	}
	return &Token{
		Value:       token,
		Label:       label,
		LastAccess:  time.Unix(lastAccess, 0),
		LastOrigin:  lastOriginIP,
		Expires:     time.Unix(expires, 0),
		Provisioned: provisioned,
	}, nil
}

// ChangeToken updates a token's label and/or expiry date
func (a *Manager) ChangeToken(userID, token string, label *string, expires *time.Time) (*Token, error) {
	if token == "" {
		return nil, errNoTokenProvided
	}
	if err := a.CanChangeToken(userID, token); err != nil {
		return nil, err
	}
	tx, err := a.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if label != nil {
		if _, err := tx.Exec(updateTokenLabelQuery, *label, userID, token); err != nil {
			return nil, err
		}
	}
	if expires != nil {
		if _, err := tx.Exec(updateTokenExpiryQuery, expires.Unix(), userID, token); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return a.Token(userID, token)
}

// RemoveToken deletes the token defined in User.Token
func (a *Manager) RemoveToken(userID, token string) error {
	if err := a.CanChangeToken(userID, token); err != nil {
		return err
	}
	return execTx(a.db, func(tx *sql.Tx) error {
		return a.removeTokenTx(tx, userID, token)
	})
}

func (a *Manager) removeTokenTx(tx *sql.Tx, userID, token string) error {
	if token == "" {
		return errNoTokenProvided
	}
	if _, err := tx.Exec(deleteTokenQuery, userID, token); err != nil {
		return err
	}
	return nil
}

// CanChangeToken checks if the token can be changed. If the token is provisioned, it cannot be changed.
func (a *Manager) CanChangeToken(userID, token string) error {
	t, err := a.Token(userID, token)
	if err != nil {
		return err
	} else if t.Provisioned {
		return ErrProvisionedTokenChange
	}
	return nil
}

// RemoveExpiredTokens deletes all expired tokens from the database
func (a *Manager) RemoveExpiredTokens() error {
	if _, err := a.db.Exec(deleteExpiredTokensQuery, time.Now().Unix()); err != nil {
		return err
	}
	return nil
}

// PhoneNumbers returns all phone numbers for the user with the given user ID
func (a *Manager) PhoneNumbers(userID string) ([]string, error) {
	rows, err := a.db.Query(selectPhoneNumbersQuery, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	phoneNumbers := make([]string, 0)
	for {
		phoneNumber, err := a.readPhoneNumber(rows)
		if errors.Is(err, ErrPhoneNumberNotFound) {
			break
		} else if err != nil {
			return nil, err
		}
		phoneNumbers = append(phoneNumbers, phoneNumber)
	}
	return phoneNumbers, nil
}

func (a *Manager) readPhoneNumber(rows *sql.Rows) (string, error) {
	var phoneNumber string
	if !rows.Next() {
		return "", ErrPhoneNumberNotFound
	}
	if err := rows.Scan(&phoneNumber); err != nil {
		return "", err
	} else if err := rows.Err(); err != nil {
		return "", err
	}
	return phoneNumber, nil
}

// AddPhoneNumber adds a phone number to the user with the given user ID
func (a *Manager) AddPhoneNumber(userID string, phoneNumber string) error {
	if _, err := a.db.Exec(insertPhoneNumberQuery, userID, phoneNumber); err != nil {
		if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return ErrPhoneNumberExists
		}
		return err
	}
	return nil
}

// RemovePhoneNumber deletes a phone number from the user with the given user ID
func (a *Manager) RemovePhoneNumber(userID string, phoneNumber string) error {
	_, err := a.db.Exec(deletePhoneNumberQuery, userID, phoneNumber)
	return err
}

// RemoveDeletedUsers deletes all users that have been marked deleted for
func (a *Manager) RemoveDeletedUsers() error {
	if _, err := a.db.Exec(deleteUsersMarkedQuery, time.Now().Unix()); err != nil {
		return err
	}
	return nil
}

// ChangeSettings persists the user settings
func (a *Manager) ChangeSettings(userID string, prefs *Prefs) error {
	b, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	if _, err := a.db.Exec(updateUserPrefsQuery, string(b), userID); err != nil {
		return err
	}
	return nil
}

// ResetStats resets all user stats in the user database. This touches all users.
func (a *Manager) ResetStats() error {
	a.mu.Lock() // Includes database query to avoid races!
	defer a.mu.Unlock()
	if _, err := a.db.Exec(updateUserStatsResetAllQuery); err != nil {
		return err
	}
	a.statsQueue = make(map[string]*Stats)
	return nil
}

// EnqueueUserStats adds the user to a queue which writes out user stats (messages, emails, ..) in
// batches at a regular interval
func (a *Manager) EnqueueUserStats(userID string, stats *Stats) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.statsQueue[userID] = stats
}

// EnqueueTokenUpdate adds the token update to  a queue which writes out token access times
// in batches at a regular interval
func (a *Manager) EnqueueTokenUpdate(tokenID string, update *TokenUpdate) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokenQueue[tokenID] = update
}

func (a *Manager) asyncQueueWriter(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		if err := a.writeUserStatsQueue(); err != nil {
			log.Tag(tag).Err(err).Warn("Writing user stats queue failed")
		}
		if err := a.writeTokenUpdateQueue(); err != nil {
			log.Tag(tag).Err(err).Warn("Writing token update queue failed")
		}
	}
}

func (a *Manager) writeUserStatsQueue() error {
	a.mu.Lock()
	if len(a.statsQueue) == 0 {
		a.mu.Unlock()
		log.Tag(tag).Trace("No user stats updates to commit")
		return nil
	}
	statsQueue := a.statsQueue
	a.statsQueue = make(map[string]*Stats)
	a.mu.Unlock()
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	log.Tag(tag).Debug("Writing user stats queue for %d user(s)", len(statsQueue))
	for userID, update := range statsQueue {
		log.
			Tag(tag).
			Fields(log.Context{
				"user_id":        userID,
				"messages_count": update.Messages,
				"emails_count":   update.Emails,
				"calls_count":    update.Calls,
			}).
			Trace("Updating stats for user %s", userID)
		if _, err := tx.Exec(updateUserStatsQuery, update.Messages, update.Emails, update.Calls, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a *Manager) writeTokenUpdateQueue() error {
	a.mu.Lock()
	if len(a.tokenQueue) == 0 {
		a.mu.Unlock()
		log.Tag(tag).Trace("No token updates to commit")
		return nil
	}
	tokenQueue := a.tokenQueue
	a.tokenQueue = make(map[string]*TokenUpdate)
	a.mu.Unlock()
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	log.Tag(tag).Debug("Writing token update queue for %d token(s)", len(tokenQueue))
	for tokenID, update := range tokenQueue {
		log.Tag(tag).Trace("Updating token %s with last access time %v", tokenID, update.LastAccess.Unix())
		if err := a.updateTokenLastAccessTx(tx, tokenID, update.LastAccess.Unix(), update.LastOrigin.String()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a *Manager) updateTokenLastAccessTx(tx *sql.Tx, token string, lastAccess int64, lastOrigin string) error {
	if _, err := tx.Exec(updateTokenLastAccessQuery, lastAccess, lastOrigin, token); err != nil {
		return err
	}
	return nil
}

// Authorize returns nil if the given user has access to the given topic using the desired
// permission. The user param may be nil to signal an anonymous user.
func (a *Manager) Authorize(user *User, topic string, perm Permission) error {
	if user != nil && user.Role == RoleAdmin {
		return nil // Admin can do everything
	}
	username := Everyone
	if user != nil {
		username = user.Name
	}
	// Select the read/write permissions for this user/topic combo.
	// - The query may return two rows (one for everyone, and one for the user), but prioritizes the user.
	// - Furthermore, the query prioritizes more specific permissions (longer!) over more generic ones, e.g. "test*" > "*"
	// - It also prioritizes write permissions over read permissions
	rows, err := a.db.Query(selectTopicPermsQuery, Everyone, username, topic)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return a.resolvePerms(a.config.DefaultAccess, perm)
	}
	var read, write bool
	if err := rows.Scan(&read, &write); err != nil {
		return err
	} else if err := rows.Err(); err != nil {
		return err
	}
	return a.resolvePerms(NewPermission(read, write), perm)
}

func (a *Manager) resolvePerms(base, perm Permission) error {
	if perm == PermissionRead && base.IsRead() {
		return nil
	} else if perm == PermissionWrite && base.IsWrite() {
		return nil
	}
	return ErrUnauthorized
}

// AddUser adds a user with the given username, password and role
func (a *Manager) AddUser(username, password string, role Role, hashed bool) error {
	return execTx(a.db, func(tx *sql.Tx) error {
		return a.addUserTx(tx, username, password, role, hashed, false)
	})
}

// AddUser adds a user with the given username, password and role
func (a *Manager) addUserTx(tx *sql.Tx, username, password string, role Role, hashed, provisioned bool) error {
	if !AllowedUsername(username) || !AllowedRole(role) {
		return ErrInvalidArgument
	}
	var hash string
	var err error = nil
	if hashed {
		hash = password
		if err := ValidPasswordHash(hash, a.config.BcryptCost); err != nil {
			return err
		}
	} else {
		hash, err = hashPassword(password, a.config.BcryptCost)
		if err != nil {
			return err
		}
	}
	userID := util.RandomStringPrefix(userIDPrefix, userIDLength)
	syncTopic, now := util.RandomStringPrefix(syncTopicPrefix, syncTopicLength), time.Now().Unix()
	if _, err = tx.Exec(insertUserQuery, userID, username, hash, role, syncTopic, provisioned, now); err != nil {
		if errors.Is(err, sqlite3.ErrConstraintUnique) {
			return ErrUserExists
		}
		return err
	}
	return nil
}

// RemoveUser deletes the user with the given username. The function returns nil on success, even
// if the user did not exist in the first place.
func (a *Manager) RemoveUser(username string) error {
	if err := a.CanChangeUser(username); err != nil {
		return err
	}
	return execTx(a.db, func(tx *sql.Tx) error {
		return a.removeUserTx(tx, username)
	})
}

func (a *Manager) removeUserTx(tx *sql.Tx, username string) error {
	if !AllowedUsername(username) {
		return ErrInvalidArgument
	}
	// Rows in user_access, user_token, etc. are deleted via foreign keys
	if _, err := tx.Exec(deleteUserQuery, username); err != nil {
		return err
	}
	return nil
}

// MarkUserRemoved sets the deleted flag on the user, and deletes all access tokens. This prevents
// successful auth via Authenticate. A background process will delete the user at a later date.
func (a *Manager) MarkUserRemoved(user *User) error {
	if !AllowedUsername(user.Name) {
		return ErrInvalidArgument
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(deleteUserAccessQuery, user.Name, user.Name); err != nil {
		return err
	}
	if _, err := tx.Exec(deleteAllTokenQuery, user.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(updateUserDeletedQuery, time.Now().Add(userHardDeleteAfterDuration).Unix(), user.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// Users returns a list of users. It always also returns the Everyone user ("*").
func (a *Manager) Users() ([]*User, error) {
	rows, err := a.db.Query(selectUsernamesQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	usernames := make([]string, 0)
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		} else if err := rows.Err(); err != nil {
			return nil, err
		}
		usernames = append(usernames, username)
	}
	rows.Close()
	users := make([]*User, 0)
	for _, username := range usernames {
		user, err := a.User(username)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// UsersCount returns the number of users in the databsae
func (a *Manager) UsersCount() (int64, error) {
	rows, err := a.db.Query(selectUserCountQuery)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, errNoRows
	}
	var count int64
	if err := rows.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// User returns the user with the given username if it exists, or ErrUserNotFound otherwise.
// You may also pass Everyone to retrieve the anonymous user and its Grant list.
func (a *Manager) User(username string) (*User, error) {
	rows, err := a.db.Query(selectUserByNameQuery, username)
	if err != nil {
		return nil, err
	}
	return a.readUser(rows)
}

// UserByID returns the user with the given ID if it exists, or ErrUserNotFound otherwise
func (a *Manager) UserByID(id string) (*User, error) {
	rows, err := a.db.Query(selectUserByIDQuery, id)
	if err != nil {
		return nil, err
	}
	return a.readUser(rows)
}

// UserByStripeCustomer returns the user with the given Stripe customer ID if it exists, or ErrUserNotFound otherwise.
func (a *Manager) UserByStripeCustomer(stripeCustomerID string) (*User, error) {
	rows, err := a.db.Query(selectUserByStripeCustomerIDQuery, stripeCustomerID)
	if err != nil {
		return nil, err
	}
	return a.readUser(rows)
}

func (a *Manager) userByToken(token string) (*User, error) {
	rows, err := a.db.Query(selectUserByTokenQuery, token, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return a.readUser(rows)
}

func (a *Manager) readUser(rows *sql.Rows) (*User, error) {
	defer rows.Close()
	var id, username, hash, role, prefs, syncTopic string
	var provisioned bool
	var stripeCustomerID, stripeSubscriptionID, stripeSubscriptionStatus, stripeSubscriptionInterval, stripeMonthlyPriceID, stripeYearlyPriceID, tierID, tierCode, tierName sql.NullString
	var messages, emails, calls int64
	var messagesLimit, messagesExpiryDuration, emailsLimit, callsLimit, reservationsLimit, attachmentFileSizeLimit, attachmentTotalSizeLimit, attachmentExpiryDuration, attachmentBandwidthLimit, stripeSubscriptionPaidUntil, stripeSubscriptionCancelAt, deleted sql.NullInt64
	if !rows.Next() {
		return nil, ErrUserNotFound
	}
	if err := rows.Scan(&id, &username, &hash, &role, &prefs, &syncTopic, &provisioned, &messages, &emails, &calls, &stripeCustomerID, &stripeSubscriptionID, &stripeSubscriptionStatus, &stripeSubscriptionInterval, &stripeSubscriptionPaidUntil, &stripeSubscriptionCancelAt, &deleted, &tierID, &tierCode, &tierName, &messagesLimit, &messagesExpiryDuration, &emailsLimit, &callsLimit, &reservationsLimit, &attachmentFileSizeLimit, &attachmentTotalSizeLimit, &attachmentExpiryDuration, &attachmentBandwidthLimit, &stripeMonthlyPriceID, &stripeYearlyPriceID); err != nil {
		return nil, err
	} else if err := rows.Err(); err != nil {
		return nil, err
	}
	user := &User{
		ID:          id,
		Name:        username,
		Hash:        hash,
		Role:        Role(role),
		Prefs:       &Prefs{},
		SyncTopic:   syncTopic,
		Provisioned: provisioned,
		Stats: &Stats{
			Messages: messages,
			Emails:   emails,
			Calls:    calls,
		},
		Billing: &Billing{
			StripeCustomerID:            stripeCustomerID.String,                                            // May be empty
			StripeSubscriptionID:        stripeSubscriptionID.String,                                        // May be empty
			StripeSubscriptionStatus:    payments.SubscriptionStatus(stripeSubscriptionStatus.String),       // May be empty
			StripeSubscriptionInterval:  payments.PriceRecurringInterval(stripeSubscriptionInterval.String), // May be empty
			StripeSubscriptionPaidUntil: time.Unix(stripeSubscriptionPaidUntil.Int64, 0),                    // May be zero
			StripeSubscriptionCancelAt:  time.Unix(stripeSubscriptionCancelAt.Int64, 0),                     // May be zero
		},
		Deleted: deleted.Valid,
	}
	if err := json.Unmarshal([]byte(prefs), user.Prefs); err != nil {
		return nil, err
	}
	if tierCode.Valid {
		// See readTier() when this is changed!
		user.Tier = &Tier{
			ID:                       tierID.String,
			Code:                     tierCode.String,
			Name:                     tierName.String,
			MessageLimit:             messagesLimit.Int64,
			MessageExpiryDuration:    time.Duration(messagesExpiryDuration.Int64) * time.Second,
			EmailLimit:               emailsLimit.Int64,
			CallLimit:                callsLimit.Int64,
			ReservationLimit:         reservationsLimit.Int64,
			AttachmentFileSizeLimit:  attachmentFileSizeLimit.Int64,
			AttachmentTotalSizeLimit: attachmentTotalSizeLimit.Int64,
			AttachmentExpiryDuration: time.Duration(attachmentExpiryDuration.Int64) * time.Second,
			AttachmentBandwidthLimit: attachmentBandwidthLimit.Int64,
			StripeMonthlyPriceID:     stripeMonthlyPriceID.String, // May be empty
			StripeYearlyPriceID:      stripeYearlyPriceID.String,  // May be empty
		}
	}
	return user, nil
}

// AllGrants returns all user-specific access control entries, mapped to their respective user IDs
func (a *Manager) AllGrants() (map[string][]Grant, error) {
	rows, err := a.db.Query(selectUserAllAccessQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := make(map[string][]Grant, 0)
	for rows.Next() {
		var userID, topic string
		var read, write, provisioned bool
		if err := rows.Scan(&userID, &topic, &read, &write, &provisioned); err != nil {
			return nil, err
		} else if err := rows.Err(); err != nil {
			return nil, err
		}
		if _, ok := grants[userID]; !ok {
			grants[userID] = make([]Grant, 0)
		}
		grants[userID] = append(grants[userID], Grant{
			TopicPattern: fromSQLWildcard(topic),
			Permission:   NewPermission(read, write),
			Provisioned:  provisioned,
		})
	}
	return grants, nil
}

// Grants returns all user-specific access control entries
func (a *Manager) Grants(username string) ([]Grant, error) {
	rows, err := a.db.Query(selectUserAccessQuery, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := make([]Grant, 0)
	for rows.Next() {
		var topic string
		var read, write, provisioned bool
		if err := rows.Scan(&topic, &read, &write, &provisioned); err != nil {
			return nil, err
		} else if err := rows.Err(); err != nil {
			return nil, err
		}
		grants = append(grants, Grant{
			TopicPattern: fromSQLWildcard(topic),
			Permission:   NewPermission(read, write),
			Provisioned:  provisioned,
		})
	}
	return grants, nil
}

// Reservations returns all user-owned topics, and the associated everyone-access
func (a *Manager) Reservations(username string) ([]Reservation, error) {
	rows, err := a.db.Query(selectUserReservationsQuery, Everyone, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	reservations := make([]Reservation, 0)
	for rows.Next() {
		var topic string
		var ownerRead, ownerWrite bool
		var everyoneRead, everyoneWrite sql.NullBool
		if err := rows.Scan(&topic, &ownerRead, &ownerWrite, &everyoneRead, &everyoneWrite); err != nil {
			return nil, err
		} else if err := rows.Err(); err != nil {
			return nil, err
		}
		reservations = append(reservations, Reservation{
			Topic:    unescapeUnderscore(topic),
			Owner:    NewPermission(ownerRead, ownerWrite),
			Everyone: NewPermission(everyoneRead.Bool, everyoneWrite.Bool), // false if null
		})
	}
	return reservations, nil
}

// HasReservation returns true if the given topic access is owned by the user
func (a *Manager) HasReservation(username, topic string) (bool, error) {
	rows, err := a.db.Query(selectUserHasReservationQuery, username, escapeUnderscore(topic))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return false, errNoRows
	}
	var count int64
	if err := rows.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// ReservationsCount returns the number of reservations owned by this user
func (a *Manager) ReservationsCount(username string) (int64, error) {
	rows, err := a.db.Query(selectUserReservationsCountQuery, username)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, errNoRows
	}
	var count int64
	if err := rows.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// ReservationOwner returns user ID of the user that owns this topic, or an
// empty string if it's not owned by anyone
func (a *Manager) ReservationOwner(topic string) (string, error) {
	rows, err := a.db.Query(selectUserReservationsOwnerQuery, escapeUnderscore(topic))
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", nil
	}
	var ownerUserID string
	if err := rows.Scan(&ownerUserID); err != nil {
		return "", err
	}
	return ownerUserID, nil
}

// ChangePassword changes a user's password
func (a *Manager) ChangePassword(username, password string, hashed bool) error {
	if err := a.CanChangeUser(username); err != nil {
		return err
	}
	return execTx(a.db, func(tx *sql.Tx) error {
		return a.changePasswordTx(tx, username, password, hashed)
	})
}

// CanChangeUser checks if the user with the given username can be changed.
// This is used to prevent changes to provisioned users, which are defined in the config file.
func (a *Manager) CanChangeUser(username string) error {
	user, err := a.User(username)
	if err != nil {
		return err
	} else if user.Provisioned {
		return ErrProvisionedUserChange
	}
	return nil
}

func (a *Manager) changePasswordTx(tx *sql.Tx, username, password string, hashed bool) error {
	var hash string
	var err error
	if hashed {
		hash = password
		if err := ValidPasswordHash(hash, a.config.BcryptCost); err != nil {
			return err
		}
	} else {
		hash, err = hashPassword(password, a.config.BcryptCost)
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec(updateUserPassQuery, hash, username); err != nil {
		return err
	}
	return nil
}

// ChangeRole changes a user's role. When a role is changed from RoleUser to RoleAdmin,
// all existing access control entries (Grant) are removed, since they are no longer needed.
func (a *Manager) ChangeRole(username string, role Role) error {
	if err := a.CanChangeUser(username); err != nil {
		return err
	}
	return execTx(a.db, func(tx *sql.Tx) error {
		return a.changeRoleTx(tx, username, role)
	})
}

func (a *Manager) changeRoleTx(tx *sql.Tx, username string, role Role) error {
	if !AllowedUsername(username) || !AllowedRole(role) {
		return ErrInvalidArgument
	}
	if _, err := tx.Exec(updateUserRoleQuery, string(role), username); err != nil {
		return err
	}
	if role == RoleAdmin {
		if _, err := tx.Exec(deleteUserAccessQuery, username, username); err != nil {
			return err
		}
	}
	return nil
}

// changeProvisionedTx changes the provisioned status of a user. This is used to mark users as
// provisioned. A provisioned user is a user defined in the config file.
func (a *Manager) changeProvisionedTx(tx *sql.Tx, username string, provisioned bool) error {
	if _, err := tx.Exec(updateUserProvisionedQuery, provisioned, username); err != nil {
		return err
	}
	return nil
}

// ChangeTier changes a user's tier using the tier code. This function does not delete reservations, messages,
// or attachments, even if the new tier has lower limits in this regard. That has to be done elsewhere.
func (a *Manager) ChangeTier(username, tier string) error {
	if !AllowedUsername(username) {
		return ErrInvalidArgument
	}
	t, err := a.Tier(tier)
	if err != nil {
		return err
	} else if err := a.checkReservationsLimit(username, t.ReservationLimit); err != nil {
		return err
	}
	if _, err := a.db.Exec(updateUserTierQuery, tier, username); err != nil {
		return err
	}
	return nil
}

// ResetTier removes the tier from the given user
func (a *Manager) ResetTier(username string) error {
	if !AllowedUsername(username) && username != Everyone && username != "" {
		return ErrInvalidArgument
	} else if err := a.checkReservationsLimit(username, 0); err != nil {
		return err
	}
	_, err := a.db.Exec(deleteUserTierQuery, username)
	return err
}

func (a *Manager) checkReservationsLimit(username string, reservationsLimit int64) error {
	u, err := a.User(username)
	if err != nil {
		return err
	}
	if u.Tier != nil && reservationsLimit < u.Tier.ReservationLimit {
		reservations, err := a.Reservations(username)
		if err != nil {
			return err
		} else if int64(len(reservations)) > reservationsLimit {
			return ErrTooManyReservations
		}
	}
	return nil
}

// AllowReservation tests if a user may create an access control entry for the given topic.
// If there are any ACL entries that are not owned by the user, an error is returned.
func (a *Manager) AllowReservation(username string, topic string) error {
	if (!AllowedUsername(username) && username != Everyone) || !AllowedTopic(topic) {
		return ErrInvalidArgument
	}
	rows, err := a.db.Query(selectOtherAccessCountQuery, escapeUnderscore(topic), escapeUnderscore(topic), username)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return errNoRows
	}
	var otherCount int
	if err := rows.Scan(&otherCount); err != nil {
		return err
	}
	if otherCount > 0 {
		return errTopicOwnedByOthers
	}
	return nil
}

// AllowAccess adds or updates an entry in th access control list for a specific user. It controls
// read/write access to a topic. The parameter topicPattern may include wildcards (*). The ACL entry
// owner may either be a user (username), or the system (empty).
func (a *Manager) AllowAccess(username string, topicPattern string, permission Permission) error {
	return execTx(a.db, func(tx *sql.Tx) error {
		return a.allowAccessTx(tx, username, topicPattern, permission, false)
	})
}

func (a *Manager) allowAccessTx(tx *sql.Tx, username string, topicPattern string, permission Permission, provisioned bool) error {
	if !AllowedUsername(username) && username != Everyone {
		return ErrInvalidArgument
	} else if !AllowedTopicPattern(topicPattern) {
		return ErrInvalidArgument
	}
	owner := ""
	if _, err := tx.Exec(upsertUserAccessQuery, username, toSQLWildcard(topicPattern), permission.IsRead(), permission.IsWrite(), owner, owner, provisioned); err != nil {
		return err
	}
	return nil
}

// ResetAccess removes an access control list entry for a specific username/topic, or (if topic is
// empty) for an entire user. The parameter topicPattern may include wildcards (*).
func (a *Manager) ResetAccess(username string, topicPattern string) error {
	return execTx(a.db, func(tx *sql.Tx) error {
		return a.resetAccessTx(tx, username, topicPattern)
	})
}

func (a *Manager) resetAccessTx(tx *sql.Tx, username string, topicPattern string) error {
	if !AllowedUsername(username) && username != Everyone && username != "" {
		return ErrInvalidArgument
	} else if !AllowedTopicPattern(topicPattern) && topicPattern != "" {
		return ErrInvalidArgument
	}
	if username == "" && topicPattern == "" {
		_, err := tx.Exec(deleteAllAccessQuery, username)
		return err
	} else if topicPattern == "" {
		_, err := tx.Exec(deleteUserAccessQuery, username, username)
		return err
	}
	_, err := tx.Exec(deleteTopicAccessQuery, username, username, toSQLWildcard(topicPattern))
	return err
}

// AddReservation creates two access control entries for the given topic: one with full read/write access for the
// given user, and one for Everyone with the permission passed as everyone. The user also owns the entries, and
// can modify or delete them.
func (a *Manager) AddReservation(username string, topic string, everyone Permission) error {
	if !AllowedUsername(username) || username == Everyone || !AllowedTopic(topic) {
		return ErrInvalidArgument
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(upsertUserAccessQuery, username, escapeUnderscore(topic), true, true, username, username, false); err != nil {
		return err
	}
	if _, err := tx.Exec(upsertUserAccessQuery, Everyone, escapeUnderscore(topic), everyone.IsRead(), everyone.IsWrite(), username, username, false); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveReservations deletes the access control entries associated with the given username/topic, as
// well as all entries with Everyone/topic. This is the counterpart for AddReservation.
func (a *Manager) RemoveReservations(username string, topics ...string) error {
	if !AllowedUsername(username) || username == Everyone || len(topics) == 0 {
		return ErrInvalidArgument
	}
	for _, topic := range topics {
		if !AllowedTopic(topic) {
			return ErrInvalidArgument
		}
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, topic := range topics {
		if _, err := tx.Exec(deleteTopicAccessQuery, username, username, escapeUnderscore(topic)); err != nil {
			return err
		}
		if _, err := tx.Exec(deleteTopicAccessQuery, Everyone, Everyone, escapeUnderscore(topic)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DefaultAccess returns the default read/write access if no access control entry matches
func (a *Manager) DefaultAccess() Permission {
	return a.config.DefaultAccess
}

// AddTier creates a new tier in the database
func (a *Manager) AddTier(tier *Tier) error {
	if tier.ID == "" {
		tier.ID = util.RandomStringPrefix(tierIDPrefix, tierIDLength)
	}
	if _, err := a.db.Exec(insertTierQuery, tier.ID, tier.Code, tier.Name, tier.MessageLimit, int64(tier.MessageExpiryDuration.Seconds()), tier.EmailLimit, tier.CallLimit, tier.ReservationLimit, tier.AttachmentFileSizeLimit, tier.AttachmentTotalSizeLimit, int64(tier.AttachmentExpiryDuration.Seconds()), tier.AttachmentBandwidthLimit, nullString(tier.StripeMonthlyPriceID), nullString(tier.StripeYearlyPriceID)); err != nil {
		return err
	}
	return nil
}

// UpdateTier updates a tier's properties in the database
func (a *Manager) UpdateTier(tier *Tier) error {
	if _, err := a.db.Exec(updateTierQuery, tier.Name, tier.MessageLimit, int64(tier.MessageExpiryDuration.Seconds()), tier.EmailLimit, tier.CallLimit, tier.ReservationLimit, tier.AttachmentFileSizeLimit, tier.AttachmentTotalSizeLimit, int64(tier.AttachmentExpiryDuration.Seconds()), tier.AttachmentBandwidthLimit, nullString(tier.StripeMonthlyPriceID), nullString(tier.StripeYearlyPriceID), tier.Code); err != nil {
		return err
	}
	return nil
}

// RemoveTier deletes the tier with the given code
func (a *Manager) RemoveTier(code string) error {
	if !AllowedTier(code) {
		return ErrInvalidArgument
	}
	// This fails if any user has this tier
	if _, err := a.db.Exec(deleteTierQuery, code); err != nil {
		return err
	}
	return nil
}

// ChangeBilling updates a user's billing fields, namely the Stripe customer ID, and subscription information
func (a *Manager) ChangeBilling(username string, billing *Billing) error {
	if _, err := a.db.Exec(updateBillingQuery, nullString(billing.StripeCustomerID), nullString(billing.StripeSubscriptionID), nullString(string(billing.StripeSubscriptionStatus)), nullString(string(billing.StripeSubscriptionInterval)), nullInt64(billing.StripeSubscriptionPaidUntil.Unix()), nullInt64(billing.StripeSubscriptionCancelAt.Unix()), username); err != nil {
		return err
	}
	return nil
}

// Tiers returns a list of all Tier structs
func (a *Manager) Tiers() ([]*Tier, error) {
	rows, err := a.db.Query(selectTiersQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tiers := make([]*Tier, 0)
	for {
		tier, err := a.readTier(rows)
		if errors.Is(err, ErrTierNotFound) {
			break
		} else if err != nil {
			return nil, err
		}
		tiers = append(tiers, tier)
	}
	return tiers, nil
}

// Tier returns a Tier based on the code, or ErrTierNotFound if it does not exist
func (a *Manager) Tier(code string) (*Tier, error) {
	rows, err := a.db.Query(selectTierByCodeQuery, code)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return a.readTier(rows)
}

// TierByStripePrice returns a Tier based on the Stripe price ID, or ErrTierNotFound if it does not exist
func (a *Manager) TierByStripePrice(priceID string) (*Tier, error) {
	rows, err := a.db.Query(selectTierByPriceIDQuery, priceID, priceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return a.readTier(rows)
}

func (a *Manager) readTier(rows *sql.Rows) (*Tier, error) {
	var id, code, name string
	var stripeMonthlyPriceID, stripeYearlyPriceID sql.NullString
	var messagesLimit, messagesExpiryDuration, emailsLimit, callsLimit, reservationsLimit, attachmentFileSizeLimit, attachmentTotalSizeLimit, attachmentExpiryDuration, attachmentBandwidthLimit sql.NullInt64
	if !rows.Next() {
		return nil, ErrTierNotFound
	}
	if err := rows.Scan(&id, &code, &name, &messagesLimit, &messagesExpiryDuration, &emailsLimit, &callsLimit, &reservationsLimit, &attachmentFileSizeLimit, &attachmentTotalSizeLimit, &attachmentExpiryDuration, &attachmentBandwidthLimit, &stripeMonthlyPriceID, &stripeYearlyPriceID); err != nil {
		return nil, err
	} else if err := rows.Err(); err != nil {
		return nil, err
	}
	// When changed, note readUser() as well
	return &Tier{
		ID:                       id,
		Code:                     code,
		Name:                     name,
		MessageLimit:             messagesLimit.Int64,
		MessageExpiryDuration:    time.Duration(messagesExpiryDuration.Int64) * time.Second,
		EmailLimit:               emailsLimit.Int64,
		CallLimit:                callsLimit.Int64,
		ReservationLimit:         reservationsLimit.Int64,
		AttachmentFileSizeLimit:  attachmentFileSizeLimit.Int64,
		AttachmentTotalSizeLimit: attachmentTotalSizeLimit.Int64,
		AttachmentExpiryDuration: time.Duration(attachmentExpiryDuration.Int64) * time.Second,
		AttachmentBandwidthLimit: attachmentBandwidthLimit.Int64,
		StripeMonthlyPriceID:     stripeMonthlyPriceID.String, // May be empty
		StripeYearlyPriceID:      stripeYearlyPriceID.String,  // May be empty
	}, nil
}

// Close closes the underlying database
func (a *Manager) Close() error {
	return a.db.Close()
}

// maybeProvisionUsersAccessAndTokens provisions users, access control entries, and tokens based on the config.
func (a *Manager) maybeProvisionUsersAccessAndTokens() error {
	if !a.config.ProvisionEnabled {
		return nil
	}
	existingUsers, err := a.Users()
	if err != nil {
		return err
	}
	provisionUsernames := util.Map(a.config.Users, func(u *User) string {
		return u.Name
	})
	return execTx(a.db, func(tx *sql.Tx) error {
		if err := a.maybeProvisionUsers(tx, provisionUsernames, existingUsers); err != nil {
			return fmt.Errorf("failed to provision users: %v", err)
		}
		if err := a.maybeProvisionGrants(tx); err != nil {
			return fmt.Errorf("failed to provision grants: %v", err)
		}
		if err := a.maybeProvisionTokens(tx, provisionUsernames); err != nil {
			return fmt.Errorf("failed to provision tokens: %v", err)
		}
		return nil
	})
}

// maybeProvisionUsers checks if the users in the config are provisioned, and adds or updates them.
// It also removes users that are provisioned, but not in the config anymore.
func (a *Manager) maybeProvisionUsers(tx *sql.Tx, provisionUsernames []string, existingUsers []*User) error {
	// Remove users that are provisioned, but not in the config anymore
	for _, user := range existingUsers {
		if user.Name == Everyone {
			continue
		} else if user.Provisioned && !util.Contains(provisionUsernames, user.Name) {
			if err := a.removeUserTx(tx, user.Name); err != nil {
				return fmt.Errorf("failed to remove provisioned user %s: %v", user.Name, err)
			}
		}
	}
	// Add or update provisioned users
	for _, user := range a.config.Users {
		if user.Name == Everyone {
			continue
		}
		existingUser, exists := util.Find(existingUsers, func(u *User) bool {
			return u.Name == user.Name
		})
		if !exists {
			if err := a.addUserTx(tx, user.Name, user.Hash, user.Role, true, true); err != nil && !errors.Is(err, ErrUserExists) {
				return fmt.Errorf("failed to add provisioned user %s: %v", user.Name, err)
			}
		} else {
			if !existingUser.Provisioned {
				if err := a.changeProvisionedTx(tx, user.Name, true); err != nil {
					return fmt.Errorf("failed to change provisioned status for user %s: %v", user.Name, err)
				}
			}
			if existingUser.Hash != user.Hash {
				if err := a.changePasswordTx(tx, user.Name, user.Hash, true); err != nil {
					return fmt.Errorf("failed to change password for provisioned user %s: %v", user.Name, err)
				}
			}
			if existingUser.Role != user.Role {
				if err := a.changeRoleTx(tx, user.Name, user.Role); err != nil {
					return fmt.Errorf("failed to change role for provisioned user %s: %v", user.Name, err)
				}
			}
		}
	}
	return nil
}

// maybyProvisionGrants removes all provisioned grants, and (re-)adds the grants from the config.
//
// Unlike users and tokens, grants can be just re-added, because they do not carry any state (such as last
// access time) or do not have dependent resources (such as grants or tokens).
func (a *Manager) maybeProvisionGrants(tx *sql.Tx) error {
	// Remove all provisioned grants
	if _, err := tx.Exec(deleteUserAccessProvisionedQuery); err != nil {
		return err
	}
	// (Re-)add provisioned grants
	for username, grants := range a.config.Access {
		user, exists := util.Find(a.config.Users, func(u *User) bool {
			return u.Name == username
		})
		if !exists && username != Everyone {
			return fmt.Errorf("user %s is not a provisioned user, refusing to add ACL entry", username)
		} else if user != nil && user.Role == RoleAdmin {
			return fmt.Errorf("adding access control entries is not allowed for admin roles for user %s", username)
		}
		for _, grant := range grants {
			if err := a.resetAccessTx(tx, username, grant.TopicPattern); err != nil {
				return fmt.Errorf("failed to reset access for user %s and topic %s: %v", username, grant.TopicPattern, err)
			}
			if err := a.allowAccessTx(tx, username, grant.TopicPattern, grant.Permission, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Manager) maybeProvisionTokens(tx *sql.Tx, provisionUsernames []string) error {
	// Remove tokens that are provisioned, but not in the config anymore
	existingTokens, err := a.allProvisionedTokens()
	if err != nil {
		return fmt.Errorf("failed to retrieve existing provisioned tokens: %v", err)
	}
	var provisionTokens []string
	for _, userTokens := range a.config.Tokens {
		for _, token := range userTokens {
			provisionTokens = append(provisionTokens, token.Value)
		}
	}
	for _, existingToken := range existingTokens {
		if !slices.Contains(provisionTokens, existingToken.Value) {
			if _, err := tx.Exec(deleteProvisionedTokenQuery, existingToken.Value); err != nil {
				return fmt.Errorf("failed to remove provisioned token %s: %v", existingToken.Value, err)
			}
		}
	}
	// (Re-)add provisioned tokens
	for username, tokens := range a.config.Tokens {
		if !slices.Contains(provisionUsernames, username) && username != Everyone {
			return fmt.Errorf("user %s is not a provisioned user, refusing to add tokens", username)
		}
		var userID string
		row := tx.QueryRow(selectUserIDFromUsernameQuery, username)
		if err := row.Scan(&userID); err != nil {
			return fmt.Errorf("failed to find provisioned user %s for provisioned tokens", username)
		}
		for _, token := range tokens {
			if _, err := a.createTokenTx(tx, userID, token.Value, token.Label, time.Unix(0, 0), netip.IPv4Unspecified(), true); err != nil {
				return err
			}
		}
	}
	return nil
}

// toSQLWildcard converts a wildcard string to a SQL wildcard string. It only allows '*' as wildcards,
// and escapes '_', assuming '\' as escape character.
func toSQLWildcard(s string) string {
	return escapeUnderscore(strings.ReplaceAll(s, "*", "%"))
}

// fromSQLWildcard converts a SQL wildcard string to a wildcard string. It converts '%' to '*',
// and removes the '\_' escape character.
func fromSQLWildcard(s string) string {
	return strings.ReplaceAll(unescapeUnderscore(s), "%", "*")
}

func escapeUnderscore(s string) string {
	return strings.ReplaceAll(s, "_", "\\_")
}

func unescapeUnderscore(s string) string {
	return strings.ReplaceAll(s, "\\_", "_")
}

func runStartupQueries(db *sql.DB, startupQueries string) error {
	if _, err := db.Exec(startupQueries); err != nil {
		return err
	}
	if _, err := db.Exec(builtinStartupQueries); err != nil {
		return err
	}
	return nil
}

func setupDB(db *sql.DB) error {
	// If 'schemaVersion' table does not exist, this must be a new database
	rowsSV, err := db.Query(selectSchemaVersionQuery)
	if err != nil {
		return setupNewDB(db)
	}
	defer rowsSV.Close()

	// If 'schemaVersion' table exists, read version and potentially upgrade
	schemaVersion := 0
	if !rowsSV.Next() {
		return errors.New("cannot determine schema version: database file may be corrupt")
	}
	if err := rowsSV.Scan(&schemaVersion); err != nil {
		return err
	}
	rowsSV.Close()

	// Do migrations
	if schemaVersion == currentSchemaVersion {
		return nil
	} else if schemaVersion > currentSchemaVersion {
		return fmt.Errorf("unexpected schema version: version %d is higher than current version %d", schemaVersion, currentSchemaVersion)
	}
	for i := schemaVersion; i < currentSchemaVersion; i++ {
		fn, ok := migrations[i]
		if !ok {
			return fmt.Errorf("cannot find migration step from schema version %d to %d", i, i+1)
		} else if err := fn(db); err != nil {
			return err
		}
	}
	return nil
}

func setupNewDB(db *sql.DB) error {
	if _, err := db.Exec(createTablesQueries); err != nil {
		return err
	}
	if _, err := db.Exec(insertSchemaVersion, currentSchemaVersion); err != nil {
		return err
	}
	return nil
}

func migrateFrom1(db *sql.DB) error {
	log.Tag(tag).Info("Migrating user database schema: from 1 to 2")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Rename user -> user_old, and create new tables
	if _, err := tx.Exec(migrate1To2CreateTablesQueries); err != nil {
		return err
	}
	// Insert users from user_old into new user table, with ID and sync_topic
	rows, err := tx.Query(migrate1To2SelectAllOldUsernamesNoTx)
	if err != nil {
		return err
	}
	defer rows.Close()
	usernames := make([]string, 0)
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return err
		}
		usernames = append(usernames, username)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, username := range usernames {
		userID := util.RandomStringPrefix(userIDPrefix, userIDLength)
		syncTopic := util.RandomStringPrefix(syncTopicPrefix, syncTopicLength)
		if _, err := tx.Exec(migrate1To2InsertUserNoTx, userID, syncTopic, username); err != nil {
			return err
		}
	}
	// Migrate old "access" table to "user_access" and drop "access" and "user_old"
	if _, err := tx.Exec(migrate1To2InsertFromOldTablesAndDropNoTx); err != nil {
		return err
	}
	if _, err := tx.Exec(updateSchemaVersion, 2); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func migrateFrom2(db *sql.DB) error {
	log.Tag(tag).Info("Migrating user database schema: from 2 to 3")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(migrate2To3UpdateQueries); err != nil {
		return err
	}
	if _, err := tx.Exec(updateSchemaVersion, 3); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateFrom3(db *sql.DB) error {
	log.Tag(tag).Info("Migrating user database schema: from 3 to 4")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(migrate3To4UpdateQueries); err != nil {
		return err
	}
	if _, err := tx.Exec(updateSchemaVersion, 4); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateFrom4(db *sql.DB) error {
	log.Tag(tag).Info("Migrating user database schema: from 4 to 5")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(migrate4To5UpdateQueries); err != nil {
		return err
	}
	if _, err := tx.Exec(updateSchemaVersion, 5); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateFrom5(db *sql.DB) error {
	log.Tag(tag).Info("Migrating user database schema: from 5 to 6")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(migrate5To6UpdateQueries); err != nil {
		return err
	}
	if _, err := tx.Exec(updateSchemaVersion, 6); err != nil {
		return err
	}
	return tx.Commit()
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullInt64(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}

// execTx executes a function in a transaction. If the function returns an error, the transaction is rolled back.
func execTx(db *sql.DB, f func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := f(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// queryTx executes a function in a transaction and returns the result. If the function
// returns an error, the transaction is rolled back.
func queryTx[T any](db *sql.DB, f func(tx *sql.Tx) (T, error)) (T, error) {
	tx, err := db.Begin()
	if err != nil {
		var zero T
		return zero, err
	}
	defer tx.Rollback()
	t, err := f(tx)
	if err != nil {
		return t, err
	}
	if err := tx.Commit(); err != nil {
		return t, err
	}
	return t, nil
}
