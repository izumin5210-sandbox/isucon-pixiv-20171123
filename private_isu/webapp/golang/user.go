package main

import (
	"fmt"
	"time"

	"github.com/izumin5210/ro"
	"github.com/izumin5210/ro/types"
)

type User struct {
	ro.Model
	ID            int       `db:"id" redis:"id"`
	AccountName   string    `db:"account_name" redis:"account_name"`
	Passhash      string    `db:"passhash" redis:"passhash"`
	Authority     int       `db:"authority" redis:"authority"`
	DelFlg        int       `db:"del_flg" redis:"del_flg"`
	CreatedAt     time.Time `db:"created_at" redis:"-"`
	CreatedAtNano int64     `redis:"created_at"`
}

func (u *User) GetKeySuffix() string {
	return fmt.Sprint(u.ID)
}

func (u *User) IsBanned() bool {
	return u.DelFlg != 0
}

var UserScorerFuncs = []types.ScorerFunc{
	func(m types.Model) (string, interface{}) {
		u := m.(*User)
		return fmt.Sprintf("accountName:%s", u.AccountName), u.DelFlg
	},
	func(m types.Model) (string, interface{}) {
		u := m.(*User)
		var s int64
		if u.DelFlg == 0 && u.Authority == 0 {
			s = u.CreatedAtNano
		}
		return "created_at", s
	},
}
