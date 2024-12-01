package auth

import (
	"encoding/base64"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type LdapAuth struct {
	url          *url.URL
	baseDN       string
	userSuffix   string
	userGroup    string
	filterDN     string
	bindDN       string
	bindPasswd   string
	timeout      time.Duration
	stopOnce     sync.Once
	stopChan     chan struct{}
	logger       *clog.CondLogger
	pool         chan ldap.Client
	hiddenDomain string
	useCache     bool
	CacheTTL     int
	userCacheMap *userCache
}

func NewLdapAuth(param_url *url.URL, logger *clog.CondLogger) (*LdapAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}

	auth := &LdapAuth{
		url:          param_url,
		timeout:      3 * time.Second,
		stopChan:     make(chan struct{}),
		logger:       logger,
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
	}

	// Only I need this. Do not care...
	var defaultBaseDN string = "DC=example,DC=com"
	auth.baseDN = getEnv[string]("DUMBPROXY_LDAP_BASEDN", defaultBaseDN)
	auth.userSuffix = getEnv[string]("DUMBPROXY_LDAP_USER_SUFFIX", "OU=people,"+auth.baseDN)
	auth.userGroup = getEnv[string]("DUMBPROXY_LDAP_USER_GROUP", "proxy")
	auth.filterDN = getEnv[string]("DUMBPROXY_LDAP_FILTER",
		fmt.Sprintf(
			"(&(objectClass=person)(uid=%%s)(memberOf=CN=%%s,OU=groups,%s))",
			auth.baseDN))
	auth.bindDN = getEnv[string]("DUMBPROXY_LDAP_BINDDN", "CN=ldap_reader,OU=people,"+auth.baseDN)
	auth.bindPasswd = getEnv[string]("DUMBPROXY_LDAP_BIND_PASSWORD", "Some_Strong_Pass")
	auth.useCache = getEnv[bool]("DUMBPROXY_LDAP_CACHE", true)
	auth.CacheTTL = getEnv[int]("DUMBPROXY_LDAP_CACHE_TTL", 60)

	poolSize := getEnv[int]("DUMBPROXY_LDAP_POOL_SIZE", 10)
	auth.pool = make(chan ldap.Client, poolSize)

	if auth.useCache {
		auth.userCacheMap = newUserCacheMap(logger)
	}

	return auth, nil
}

func (l *LdapAuth) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		for {
			select {
			case con := <-l.pool:
				con.Close()
			default:
				return
			}
		}
	})
}

func (l *LdapAuth) cacheUser(login, password string, inLdap bool) {
	cacheTTL := time.Duration(l.CacheTTL) * time.Second
	if l.useCache {
		var msg string
		msg_cache := ", caching for %s"
		if inLdap {
			msg = "Add %q to Allow list"
		} else {
			msg = "Add %q to Deny list"
		}
		l.logger.Info(
			fmt.Sprintf(msg+msg_cache, login, cacheTTL.String()),
		)
		go l.userCacheMap.add(login, password, inLdap, cacheTTL)
	}
}

func (l *LdapAuth) verifyLdapLoginAndPassword(login, password string,
	wr http.ResponseWriter, req *http.Request) bool {

	if l.useCache {
		if inCache, allowed := l.userCacheMap.get(login, password); inCache {
			return allowed
		}
	}

	client, err := l.getConnection()
	if err != nil {
		l.logger.Critical(err.Error())
		return false
	}
	defer l.stashConnection(client)

	ldapRequest := ldap.NewSearchRequest(
		l.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(l.timeout/time.Second),
		false,
		fmt.Sprintf(l.filterDN, ldap.EscapeFilter(login), ldap.EscapeFilter(l.userGroup)),
		[]string{"dn"},
		nil,
	)

	sr, err := client.Search(ldapRequest)
	if err != nil {
		l.logger.Error(fmt.Sprintf("Ldap search for %q failed: %v", login, err))
		return false
	}

	if len(sr.Entries) > 1 {
		l.logger.Debug(fmt.Sprintf("Too many results found for %s", login))
		return false
	}
	if len(sr.Entries) == 0 {
		l.logger.Debug(fmt.Sprintf("No results found for %s", login))
		l.cacheUser(login, password, false)
		return false
	}

	loginBindDN := fmt.Sprintf("CN=%s,%s", login, l.userSuffix)
	err = client.Bind(loginBindDN, password)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			l.logger.Info(fmt.Sprintf("Failed to authenticate %q", login))
			l.cacheUser(login, password, false)
			return false
		}
		l.logger.Error(fmt.Sprintf("Bind with %q failed: %v", login, err))
		return false
	}

	l.cacheUser(login, password, true)
	return true
}

func (l *LdapAuth) Validate(wr http.ResponseWriter, req *http.Request) (string, bool) {
	hdr := req.Header.Get("Proxy-Authorization")
	if hdr == "" {
		requireBasicAuth(wr, req, l.hiddenDomain)
		return "", false
	}
	hdr_parts := strings.SplitN(hdr, " ", 2)
	if len(hdr_parts) != 2 || strings.ToLower(hdr_parts[0]) != "basic" {
		requireBasicAuth(wr, req, l.hiddenDomain)
		return "", false
	}

	token := hdr_parts[1]
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		requireBasicAuth(wr, req, l.hiddenDomain)
		return "", false
	}

	pair := strings.SplitN(string(data), ":", 2)
	if len(pair) != 2 {
		requireBasicAuth(wr, req, l.hiddenDomain)
		return "", false
	}

	login := pair[0]
	password := pair[1]

	if l.verifyLdapLoginAndPassword(login, password, wr, req) {
		if l.hiddenDomain != "" &&
			(req.Host == l.hiddenDomain || req.URL.Host == l.hiddenDomain) {
			wr.Header().Set("Content-Length", strconv.Itoa(len([]byte(AUTH_TRIGGERED_MSG))))
			wr.Header().Set("Pragma", "no-cache")
			wr.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			wr.Header().Set("Expires", EPOCH_EXPIRE)
			wr.Header()["Date"] = nil
			wr.WriteHeader(http.StatusOK)
			wr.Write([]byte(AUTH_TRIGGERED_MSG))
			return "", false
		} else {
			return login, true
		}
	}
	requireBasicAuth(wr, req, l.hiddenDomain)
	return "", false
}

func (l *LdapAuth) getConnection() (ldap.Client, error) {
	var client ldap.Client
	select {
	case client = <-l.pool:
		if err := client.Bind(l.bindDN, l.bindPasswd); err == nil {
			return client, nil
		}
		client.Close()
	default:
	}

	var err error
	client, err = ldap.DialURL(l.url.String())
	if err != nil {
		return nil, fmt.Errorf("Dial to %q failed: %v", l.url.String(), err)
	}

	if err := client.Bind(l.bindDN, l.bindPasswd); err != nil {
		client.Close()
		return nil, fmt.Errorf("Bind with %q failed: %v", l.bindDN, err)
	}

	return client, nil
}

func (l *LdapAuth) stashConnection(client ldap.Client) {
	select {
	case l.pool <- client:
		return
	default:
		client.Close()
		return
	}
}

func getEnv[T any](key string, defaultValue T) T {
	var result T

	value, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue
	}

	switch any(result).(type) {
	case int:
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return result
		}
		return any(intValue).(T)
	case bool:
		boolValue, err := strconv.ParseBool(value)
		if err != nil {
			return result
		}
		return any(boolValue).(T)
	case string:
		return any(value).(T)
	default:
		fmt.Fprintf(os.Stderr, "ERROR: unsupported type of environ %q\n", key)
		os.Exit(1)
		return result
	}
}
