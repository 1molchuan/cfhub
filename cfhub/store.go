package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY,          -- linux.do user id (never changes)
  username    TEXT    NOT NULL,
  name        TEXT    NOT NULL DEFAULT '',
  trust_level INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  last_login  INTEGER NOT NULL,
  banned      INTEGER NOT NULL DEFAULT 0,
  ban_reason  TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tokens (
  hash       TEXT    PRIMARY KEY,           -- sha256 of the token; the token itself is never stored
  user_id    INTEGER NOT NULL,
  prefix     TEXT    NOT NULL,              -- first characters, to tell tokens apart in the UI
  created_at INTEGER NOT NULL,
  last_used  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens(user_id);
CREATE TABLE IF NOT EXISTS reports (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL,
  at       INTEGER NOT NULL,
  prefix   TEXT    NOT NULL,                -- reporter's /24 (IPv6 /48); the full address is not kept
  isp      TEXT    NOT NULL,
  family   INTEGER NOT NULL,
  ips      TEXT    NOT NULL,                -- JSON [ReportIP], best first
  dropped  INTEGER NOT NULL DEFAULT 0,      -- addresses rejected (not Cloudflare, malformed)
  version  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS reports_at   ON reports(at);
CREATE INDEX IF NOT EXISTS reports_user ON reports(user_id, family, at);
CREATE INDEX IF NOT EXISTS reports_prober ON reports(user_id, prefix, family, at);
CREATE TABLE IF NOT EXISTS pool_history (
  at        INTEGER NOT NULL,
  isp       TEXT    NOT NULL,
  family    INTEGER NOT NULL,
  ips       TEXT    NOT NULL,               -- JSON []string
  users     INTEGER NOT NULL,
  median_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pool_history_key ON pool_history(isp, family, at);
-- Uptime per prober for the thanks list: hours in which it sent an IPv4 report. Kept after reports are
-- pruned. IPv4 only, so a dual-stack machine (one v4 and one v6 prefix) counts once.
CREATE TABLE IF NOT EXISTS prober_uptime (
  user_id   INTEGER NOT NULL,
  prefix    TEXT    NOT NULL,
  first_at  INTEGER NOT NULL,
  last_hour INTEGER NOT NULL,              -- unix time / 3600
  hours     INTEGER NOT NULL,
  PRIMARY KEY (user_id, prefix)
);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

type User struct {
	ID         int64
	Username   string
	Name       string
	TrustLevel int
	CreatedAt  int64
	LastLogin  int64
	Banned     bool
	BanReason  string
}

type ReportIP struct {
	IP       string `json:"ip"`
	MedianMS int    `json:"median_ms"`
	OK       int    `json:"ok"`
	Rounds   int    `json:"rounds"`
}

type Report struct {
	ID      int64
	UserID  int64
	At      int64
	Prefix  string
	ISP     string
	Family  int
	IPs     []ReportIP
	Dropped int
	Version string
}

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	// One connection: the write volume is tiny and this rules out SQLITE_BUSY between our own goroutines.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	// Uptime arrived after the first reports: count those once from the reports still kept.
	if s.Setting("uptime_backfilled") != "1" {
		if _, err := db.Exec(`INSERT OR IGNORE INTO prober_uptime (user_id, prefix, first_at, last_hour, hours)
			SELECT user_id, prefix, MIN(at), MAX(at / 3600), COUNT(DISTINCT at / 3600) FROM reports WHERE family = 4 GROUP BY user_id, prefix`); err != nil {
			db.Close()
			return nil, err
		}
		if err := s.SetSetting("uptime_backfilled", "1"); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// UpsertUser records a login. Ban state and creation time survive re-logins.
func (s *Store) UpsertUser(u User, now int64) (User, error) {
	_, err := s.db.Exec(`INSERT INTO users (id, username, name, trust_level, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET username = excluded.username, name = excluded.name, trust_level = excluded.trust_level, last_login = excluded.last_login`,
		u.ID, u.Username, u.Name, u.TrustLevel, now, now)
	if err != nil {
		return User{}, err
	}
	return s.GetUser(u.ID)
}

func (s *Store) GetUser(id int64) (User, error) {
	var u User
	var banned int
	err := s.db.QueryRow(`SELECT id, username, name, trust_level, created_at, last_login, banned, ban_reason FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Name, &u.TrustLevel, &u.CreatedAt, &u.LastLogin, &banned, &u.BanReason)
	u.Banned = banned != 0
	return u, err
}

type UserRow struct {
	User
	TokenPrefix string
	LastReport  int64
	Reports24h  int
	LastISP     string
}

func (s *Store) ListUsers(since24h int64) ([]UserRow, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.name, u.trust_level, u.created_at, u.last_login, u.banned, u.ban_reason,
		COALESCE((SELECT prefix FROM tokens t WHERE t.user_id = u.id ORDER BY created_at DESC LIMIT 1), ''),
		COALESCE((SELECT MAX(at) FROM reports r WHERE r.user_id = u.id), 0),
		(SELECT COUNT(*) FROM reports r WHERE r.user_id = u.id AND r.at >= ?),
		COALESCE((SELECT isp FROM reports r WHERE r.user_id = u.id ORDER BY at DESC LIMIT 1), '')
		FROM users u ORDER BY u.last_login DESC`, since24h)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var r UserRow
		var banned int
		if err := rows.Scan(&r.ID, &r.Username, &r.Name, &r.TrustLevel, &r.CreatedAt, &r.LastLogin, &banned, &r.BanReason,
			&r.TokenPrefix, &r.LastReport, &r.Reports24h, &r.LastISP); err != nil {
			return nil, err
		}
		r.Banned = banned != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SetBanned(id int64, banned bool, reason string) error {
	flag := 0
	if banned {
		flag = 1
	}
	_, err := s.db.Exec(`UPDATE users SET banned = ?, ban_reason = ? WHERE id = ?`, flag, reason, id)
	return err
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RotateToken replaces the user's token and returns the new one. Only its hash is stored, so this is
// the only moment it can be shown.
func (s *Store) RotateToken(userID int64, now int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := "cfp_" + base64.RawURLEncoding.EncodeToString(raw)
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM tokens WHERE user_id = ?`, userID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`INSERT INTO tokens (hash, user_id, prefix, created_at) VALUES (?, ?, ?, ?)`, hashToken(token), userID, token[:10], now); err != nil {
		return "", err
	}
	return token, tx.Commit()
}

func (s *Store) RevokeTokens(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM tokens WHERE user_id = ?`, userID)
	return err
}

// TokenInfo returns the prefix and creation time of the user's token ("" when there is none).
func (s *Store) TokenInfo(userID int64) (prefix string, createdAt, lastUsed int64, err error) {
	err = s.db.QueryRow(`SELECT prefix, created_at, last_used FROM tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, userID).Scan(&prefix, &createdAt, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, 0, nil
	}
	return prefix, createdAt, lastUsed, err
}

var errBadToken = errors.New("invalid token")

// UserForToken resolves a bearer token to its (not banned) user and marks the token used.
func (s *Store) UserForToken(token string, now int64) (User, error) {
	if !strings.HasPrefix(token, "cfp_") || len(token) > 64 {
		return User{}, errBadToken
	}
	hash := hashToken(token)
	var userID int64
	if err := s.db.QueryRow(`SELECT user_id FROM tokens WHERE hash = ?`, hash).Scan(&userID); err != nil {
		return User{}, errBadToken
	}
	u, err := s.GetUser(userID)
	if err != nil {
		return User{}, errBadToken
	}
	_, _ = s.db.Exec(`UPDATE tokens SET last_used = ? WHERE hash = ?`, now, hash)
	return u, nil
}

func (s *Store) InsertReport(r Report) error {
	ips, err := json.Marshal(r.IPs)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO reports (user_id, at, prefix, isp, family, ips, dropped, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.UserID, r.At, r.Prefix, r.ISP, r.Family, string(ips), r.Dropped, r.Version)
	if err != nil || r.Family != 4 {
		return err
	}
	// A new hour for this prober adds one hour of uptime.
	_, err = s.db.Exec(`INSERT INTO prober_uptime (user_id, prefix, first_at, last_hour, hours) VALUES (?, ?, ?, ?, 1)
		ON CONFLICT (user_id, prefix) DO UPDATE SET hours = hours + (excluded.last_hour > last_hour), last_hour = MAX(last_hour, excluded.last_hour)`,
		r.UserID, r.Prefix, r.At, r.At/3600)
	return err
}

// Leader is one line of the thanks list.
type Leader struct {
	Username string
	Hours    int   // summed over the user's probers
	Probers  int   // probers ever seen
	Online   int   // probers that reported in the last two hours
	Since    int64 // first report
}

// Leaders ranks users (not banned) by the uptime of all their probers.
func (s *Store) Leaders(now int64, limit int) ([]Leader, error) {
	rows, err := s.db.Query(`SELECT u.username, SUM(p.hours), COUNT(*), SUM(p.last_hour >= ?), MIN(p.first_at)
		FROM prober_uptime p JOIN users u ON u.id = p.user_id WHERE u.banned = 0
		GROUP BY p.user_id ORDER BY SUM(p.hours) DESC, MIN(p.first_at) LIMIT ?`, now/3600-2, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Leader
	for rows.Next() {
		var l Leader
		if err := rows.Scan(&l.Username, &l.Hours, &l.Probers, &l.Online, &l.Since); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// LastReportAt is when this prober (user + reporter prefix) last reported this family.
func (s *Store) LastReportAt(userID int64, prefix string, family int) (int64, error) {
	var at sql.NullInt64
	err := s.db.QueryRow(`SELECT MAX(at) FROM reports WHERE user_id = ? AND prefix = ? AND family = ?`, userID, prefix, family).Scan(&at)
	return at.Int64, err
}

func scanReports(rows *sql.Rows) ([]Report, error) {
	defer rows.Close()
	var out []Report
	for rows.Next() {
		var r Report
		var ips string
		if err := rows.Scan(&r.ID, &r.UserID, &r.At, &r.Prefix, &r.ISP, &r.Family, &ips, &r.Dropped, &r.Version); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(ips), &r.IPs); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveReports returns reports since `since` from users who are not banned, newest first.
func (s *Store) ActiveReports(since int64) ([]Report, error) {
	rows, err := s.db.Query(`SELECT r.id, r.user_id, r.at, r.prefix, r.isp, r.family, r.ips, r.dropped, r.version
		FROM reports r JOIN users u ON u.id = r.user_id WHERE r.at >= ? AND u.banned = 0 ORDER BY r.at DESC, r.id DESC`, since)
	if err != nil {
		return nil, err
	}
	return scanReports(rows)
}

func (s *Store) UserReports(userID int64, limit int) ([]Report, error) {
	rows, err := s.db.Query(`SELECT id, user_id, at, prefix, isp, family, ips, dropped, version FROM reports WHERE user_id = ? ORDER BY at DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	return scanReports(rows)
}

type HistoryRow struct {
	At       int64    `json:"at"`
	IPs      []string `json:"ips"`
	Users    int      `json:"probers"`
	MedianMS int      `json:"median_ms"`
}

func (s *Store) InsertHistory(at int64, isp string, family int, ips []string, users, medianMS int) error {
	raw, err := json.Marshal(ips)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO pool_history (at, isp, family, ips, users, median_ms) VALUES (?, ?, ?, ?, ?, ?)`, at, isp, family, string(raw), users, medianMS)
	return err
}

func (s *Store) History(isp string, family int, since int64) ([]HistoryRow, error) {
	rows, err := s.db.Query(`SELECT at, ips, users, median_ms FROM pool_history WHERE isp = ? AND family = ? AND at >= ? ORDER BY at`, isp, family, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HistoryRow{}
	for rows.Next() {
		var h HistoryRow
		var ips string
		if err := rows.Scan(&h.At, &ips, &h.Users, &h.MedianMS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ips), &h.IPs)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) LastHistory(isp string, family int) (HistoryRow, bool, error) {
	var h HistoryRow
	var ips string
	err := s.db.QueryRow(`SELECT at, ips, users, median_ms FROM pool_history WHERE isp = ? AND family = ? ORDER BY at DESC LIMIT 1`, isp, family).Scan(&h.At, &ips, &h.Users, &h.MedianMS)
	if errors.Is(err, sql.ErrNoRows) {
		return h, false, nil
	}
	if err != nil {
		return h, false, err
	}
	_ = json.Unmarshal([]byte(ips), &h.IPs)
	return h, true, nil
}

// Prune drops reports and history past their retention.
func (s *Store) Prune(reportsBefore, historyBefore int64) error {
	if _, err := s.db.Exec(`DELETE FROM reports WHERE at < ?`, reportsBefore); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM pool_history WHERE at < ?`, historyBefore)
	return err
}

func (s *Store) Setting(key string) string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func unixNow() int64 { return time.Now().Unix() }
