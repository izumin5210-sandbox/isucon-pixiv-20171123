package main

import (
	"fmt"
	"time"

	"github.com/izumin5210/ro"
	"github.com/izumin5210/ro/types"
)

type Comment struct {
	ro.Model
	ID            int       `db:"id" redis:"id"`
	PostID        int       `db:"post_id" redis:"post_id"`
	UserID        int       `db:"user_id" redis:"user_id"`
	Comment       string    `db:"comment" redis:"comment"`
	CreatedAt     time.Time `db:"created_at"`
	CreatedAtNano int64     `redis:"created_at"`
	User          *User     `redis:"-"`
}

func (c *Comment) GetKeySuffix() string {
	return fmt.Sprint(c.ID)
}

var CommentScorerFuncs = []types.ScorerFunc{
	func(m types.Model) (string, interface{}) {
		return "post", m.(*Comment).PostID
	},
	func(m types.Model) (string, interface{}) {
		return "user", m.(*Comment).UserID
	},
	func(m types.Model) (string, interface{}) {
		return "created_at", m.(*Comment).CreatedAtNano
	},
}
