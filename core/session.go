package core

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"
)

type SessionConfig struct {
	CookieName string
	MaxAge     int
	Secure     bool
	HttpOnly   bool
	SameSite   SameSite
	Path       string
	Store      SessionStore
}

type SessionStore interface {
	Get(id string) (map[string]any, bool)
	Save(id string, data map[string]any, maxAge int)
	Delete(id string)
}

type Session struct {
	id       string
	data     map[string]any
	modified bool
	store    SessionStore
	maxAge   int
}

func (s *Session) Get(key string) (any, bool) {
	v, ok := s.data[key]
	return v, ok
}

func (s *Session) GetString(key string) string {
	v, ok := s.data[key]
	if !ok {
		return ""
	}
	str, _ := v.(string)
	return str
}

func (s *Session) Set(key string, value any) {
	s.data[key] = value
	s.modified = true
}

func (s *Session) Delete(key string) {
	delete(s.data, key)
	s.modified = true
}

func (s *Session) Clear() {
	for k := range s.data {
		delete(s.data, k)
	}
	s.modified = true
}

func (s *Session) ID() string {
	return s.id
}

type memSessionEntry struct {
	data      map[string]any
	expiresAt int64
}

type MemorySessionStore struct {
	entries *ShardedMap[string, *memSessionEntry]
	running atomic.Bool
}

func NewMemorySessionStore() *MemorySessionStore {
	s := &MemorySessionStore{
		entries: NewShardedMap[string, *memSessionEntry](StringHash),
	}
	s.startCleanup()
	return s
}

func (s *MemorySessionStore) startCleanup() {
	if s.running.CompareAndSwap(false, true) {
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			for range ticker.C {
				now := CoarseNanotime()
				s.entries.Range(func(key string, entry *memSessionEntry) bool {
					if entry.expiresAt > 0 && now > entry.expiresAt {
						s.entries.Delete(key)
					}
					return true
				})
			}
		}()
	}
}

func (s *MemorySessionStore) Get(id string) (map[string]any, bool) {
	entry, ok := s.entries.Load(id)
	if !ok {
		return nil, false
	}
	now := CoarseNanotime()
	if entry.expiresAt > 0 && now > entry.expiresAt {
		s.entries.Delete(id)
		return nil, false
	}
	cp := make(map[string]any, len(entry.data))
	for k, v := range entry.data {
		cp[k] = v
	}
	return cp, true
}

func (s *MemorySessionStore) Save(id string, data map[string]any, maxAge int) {
	cp := make(map[string]any, len(data))
	for k, v := range data {
		cp[k] = v
	}
	var expiresAt int64
	if maxAge > 0 {
		expiresAt = CoarseNanotime() + int64(maxAge)*1_000_000_000
	}
	s.entries.Store(id, &memSessionEntry{
		data:      cp,
		expiresAt: expiresAt,
	})
}

func (s *MemorySessionStore) Delete(id string) {
	s.entries.Delete(id)
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func Sessions(cfg SessionConfig) MiddlewareFunc {
	if cfg.CookieName == "" {
		cfg.CookieName = "alos_session"
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 86400
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if cfg.Store == nil {
		cfg.Store = NewMemorySessionStore()
	}

	cookieName := cfg.CookieName
	maxAge := cfg.MaxAge
	store := cfg.Store
	path := cfg.Path
	secure := cfg.Secure
	httpOnly := cfg.HttpOnly
	sameSite := cfg.SameSite

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			sid := req.Cookie(cookieName)
			var data map[string]any
			var isNew bool

			if sid != "" {
				var ok bool
				data, ok = store.Get(sid)
				if !ok {
					sid = generateSessionID()
					data = make(map[string]any)
					isNew = true
				}
			} else {
				sid = generateSessionID()
				data = make(map[string]any)
				isNew = true
			}

			sess := &Session{
				id:       sid,
				data:     data,
				modified: false,
				store:    store,
				maxAge:   maxAge,
			}

			req.Set("session", sess)
			next(req, resp)

			if sess.modified || isNew {
				store.Save(sess.id, sess.data, maxAge)
				resp.SetCookie(Cookie{
					Name:     cookieName,
					Value:    sess.id,
					Path:     path,
					MaxAge:   maxAge,
					Secure:   secure,
					HttpOnly: httpOnly,
					SameSite: sameSite,
				})
			}
		}
	}
}

func GetSession(req *Request) *Session {
	v, ok := req.Get("session")
	if !ok {
		return nil
	}
	sess, _ := v.(*Session)
	return sess
}
