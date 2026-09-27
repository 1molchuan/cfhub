package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookie = "cfhub_session"
	oauthCookie   = "cfhub_oauth"
	sessionMaxAge = 30 * 24 * time.Hour
	oauthMaxAge   = 10 * time.Minute
)

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Hub) sign(purpose, payload string) string {
	mac := hmac.New(sha256.New, h.cfg.SessionKey)
	mac.Write([]byte(purpose + "\x00" + payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Hub) verify(purpose, payload, sig string) bool {
	return hmac.Equal([]byte(h.sign(purpose, payload)), []byte(sig))
}

func (h *Hub) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(maxAge.Seconds()),
		HttpOnly: true, Secure: strings.HasPrefix(h.cfg.PublicURL, "https://"), SameSite: http.SameSiteLaxMode,
	})
}

func (h *Hub) clearCookie(w http.ResponseWriter, name string) { h.setCookie(w, name, "", -time.Second) }

// signedValue packs fields with an HMAC and an expiry: "f1|f2|...|exp|sig".
func (h *Hub) signedValue(purpose string, maxAge time.Duration, fields ...string) string {
	payload := strings.Join(append(fields, strconv.FormatInt(time.Now().Add(maxAge).Unix(), 10)), "|")
	return payload + "|" + h.sign(purpose, payload)
}

func (h *Hub) openValue(purpose, value string, count int) ([]string, bool) {
	parts := strings.Split(value, "|")
	if len(parts) != count+2 {
		return nil, false
	}
	payload := strings.Join(parts[:count+1], "|")
	if !h.verify(purpose, payload, parts[count+1]) {
		return nil, false
	}
	exp, err := strconv.ParseInt(parts[count], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil, false
	}
	return parts[:count], true
}

// session is the signed-in user (if any) and the raw cookie the CSRF token is derived from.
type session struct {
	User  User
	Raw   string
	Admin bool
}

func (h *Hub) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	fields, ok := h.openValue("session", c.Value, 1)
	if !ok {
		return session{}, false
	}
	id, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return session{}, false
	}
	u, err := h.store.GetUser(id)
	if err != nil {
		return session{}, false
	}
	return session{User: u, Raw: c.Value, Admin: h.cfg.Admins[u.ID]}, true
}

func (h *Hub) csrfToken(s session) string {
	if s.Raw == "" {
		return ""
	}
	return h.sign("csrf", s.Raw)[:32]
}

// checkPost guards every state-changing form: signed in, a CSRF token bound to the session, and (when
// the browser sends one) an Origin matching this site.
func (h *Hub) checkPost(w http.ResponseWriter, r *http.Request) (session, bool) {
	s, ok := h.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/join", http.StatusSeeOther)
		return session{}, false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.origin() {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return session{}, false
	}
	if err := r.ParseForm(); err != nil || !hmac.Equal([]byte(r.PostFormValue("csrf")), []byte(h.csrfToken(s))) {
		http.Error(w, "invalid or expired form, reload the page", http.StatusForbidden)
		return session{}, false
	}
	return s, true
}

func (h *Hub) origin() string {
	u, err := url.Parse(h.cfg.PublicURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (h *Hub) redirectURI() string { return strings.TrimRight(h.cfg.PublicURL, "/") + "/auth/callback" }

// GET /login — start linux.do Connect: authorization code with state and PKCE (S256).
func (h *Hub) handleLogin(w http.ResponseWriter, r *http.Request) {
	if h.cfg.ClientID == "" {
		h.renderMessage(w, r, http.StatusServiceUnavailable, "登录暂未开放", "站点还没有配置 linux.do 登录。")
		return
	}
	state, verifier := randomToken(18), randomToken(32)
	h.setCookie(w, oauthCookie, h.signedValue("oauth", oauthMaxAge, state, verifier), oauthMaxAge)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {h.cfg.ClientID},
		"redirect_uri":          {h.redirectURI()},
		"scope":                 {"user"},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, h.cfg.AuthorizeURL+"?"+q.Encode(), http.StatusFound)
}

type linuxdoUser struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	TrustLevel int    `json:"trust_level"`
	Active     bool   `json:"active"`
	Silenced   bool   `json:"silenced"`
}

func (h *Hub) exchangeCode(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {h.redirectURI()},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(h.cfg.ClientID, h.cfg.ClientSecret) // as new-api does against linux.do (no form-escaping)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := h.oauthClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return "", fmt.Errorf("token endpoint: HTTP %d, unreadable reply", resp.StatusCode)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("token endpoint: HTTP %d %s %s %s", resp.StatusCode, body.Error, body.ErrorDescription, body.Message)
	}
	return body.AccessToken, nil
}

func (h *Hub) fetchLinuxdoUser(ctx context.Context, accessToken string) (linuxdoUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.UserURL, nil)
	if err != nil {
		return linuxdoUser{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := h.oauthClient.Do(req)
	if err != nil {
		return linuxdoUser{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return linuxdoUser{}, fmt.Errorf("user endpoint: HTTP %d", resp.StatusCode)
	}
	var u linuxdoUser
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&u); err != nil {
		return linuxdoUser{}, err
	}
	if u.ID <= 0 || u.Username == "" {
		return linuxdoUser{}, errors.New("user endpoint returned no id")
	}
	return u, nil
}

// GET /auth/callback
func (h *Hub) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		h.renderMessage(w, r, http.StatusBadRequest, "登录未完成", "linux.do 返回:"+e+" "+q.Get("error_description"))
		return
	}
	c, err := r.Cookie(oauthCookie)
	var fields []string
	ok := err == nil
	if ok {
		fields, ok = h.openValue("oauth", c.Value, 2)
	}
	h.clearCookie(w, oauthCookie)
	if !ok || !hmac.Equal([]byte(fields[0]), []byte(q.Get("state"))) || q.Get("code") == "" {
		h.renderMessage(w, r, http.StatusBadRequest, "登录已过期", "请重新点击登录(登录链接 10 分钟内有效)。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	token, err := h.exchangeCode(ctx, q.Get("code"), fields[1])
	if err != nil {
		log.Printf("oauth: %v", err)
		h.renderMessage(w, r, http.StatusBadGateway, "登录失败", "无法向 linux.do 换取登录凭据,请稍后再试。")
		return
	}
	lu, err := h.fetchLinuxdoUser(ctx, token)
	if err != nil {
		log.Printf("oauth: %v", err)
		h.renderMessage(w, r, http.StatusBadGateway, "登录失败", "无法读取 linux.do 账号信息,请稍后再试。")
		return
	}
	if !lu.Active || lu.Silenced || lu.TrustLevel < h.cfg.MinTrust {
		h.renderMessage(w, r, http.StatusForbidden, "暂时无法加入",
			fmt.Sprintf("需要 linux.do 信任等级 %d 及以上、账号已激活且未被禁言。你当前的信任等级是 %d。", h.cfg.MinTrust, lu.TrustLevel))
		return
	}
	u, err := h.store.UpsertUser(User{ID: lu.ID, Username: lu.Username, Name: lu.Name, TrustLevel: lu.TrustLevel}, unixNow())
	if err != nil {
		log.Printf("oauth: store user: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	h.setCookie(w, sessionCookie, h.signedValue("session", sessionMaxAge, strconv.FormatInt(u.ID, 10)), sessionMaxAge)
	http.Redirect(w, r, "/join", http.StatusSeeOther)
}

// POST /logout
func (h *Hub) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.checkPost(w, r); !ok {
		return
	}
	h.clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
