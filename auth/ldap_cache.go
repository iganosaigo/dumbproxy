package auth

import (
	"fmt"
	"sync"
	"time"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type user struct {
	login    string
	password string
	inLdap   bool
	Timer    *time.Timer
}

type userCache struct {
	mu     sync.Mutex
	data   map[string]*user
	logger *clog.CondLogger
}

func newUserCacheMap(logger *clog.CondLogger) *userCache {
	return &userCache{
		data:   make(map[string]*user),
		logger: logger,
	}
}

func (u *userCache) add(login, password string, inLdap bool, duration time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// not touching if cache still valid.
	if item, exists := u.data[login]; exists && item.Timer != nil {
		// item.Timer.Stop()
		// item.Timer = nil
		return
	}

	timer := time.AfterFunc(duration, func() {
		u.delete(login)
	})

	u.data[login] = &user{
		login:    login,
		password: password,
		inLdap:   inLdap,
		Timer:    timer,
	}
	var msg string
	msg_cache := ", caching for %s"
	if inLdap {
		msg = "Add %q to Allow list"
	} else {
		msg = "Add %q to Deny list"
	}
	u.logger.Info(
		fmt.Sprintf(msg+msg_cache, login, duration.String()),
	)
}

func (u *userCache) delete(login string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if item, exists := u.data[login]; exists {
		if item.Timer != nil {
			item.Timer.Stop()
			item.Timer = nil
		}
		delete(u.data, login)
		u.logger.Info(fmt.Sprintf("Expire cache for %q", login))
	}
}

func (u *userCache) get(login, password string) (inCache, allow bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	user, exists := u.data[login]
	if !exists {
		inCache, allow = false, false
	} else {
		if password != user.password {
			u.logger.Info(fmt.Sprintf("Cached and request password mismatch for %q", login))
			inCache, allow = true, false
		} else {
			inCache, allow = true, user.inLdap
		}
	}
	return
}
