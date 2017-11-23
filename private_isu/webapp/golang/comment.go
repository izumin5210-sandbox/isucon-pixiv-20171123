package main

import (
	"fmt"
	"time"

	"github.com/izumin5210/ro"
	"github.com/izumin5210/ro/types"
)

type Comment struct {
	ro.Model
	ID        int       `db:"id" redis:"id"`
	PostID    int       `db:"post_id" redis:"post_id"`
	UserID    int       `db:"user_id" redis:"user_id"`
	Comment   string    `db:"comment" redis:"comment"`
	CreatedAt time.Time `db:"created_at" redis:"created_at"`
	User      *User
}

func (c *Comment) GetKeySuffix() string {
	return fmt.Sprint(c.ID)
}

var CommentScorerMap = map[string]types.ScorerFunc{
	"post": func(m types.Model) interface{} {
		return m.(*Comment).PostID
	},
	"user": func(m types.Model) interface{} {
		return m.(*Comment).UserID
	},
	"created_at": func(m types.Model) interface{} {
		return m.(*Comment).CreatedAt.UnixNano()
	},
}
