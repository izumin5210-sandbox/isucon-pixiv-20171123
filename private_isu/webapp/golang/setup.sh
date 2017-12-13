#!/bin/bash

go get -u "github.com/bradfitz/gomemcache/memcache"
go get -u "github.com/bradleypeabody/gorilla-sessions-memcache"
go get -u "github.com/go-sql-driver/mysql"
go get -u "github.com/gorilla/sessions"
go get -u "github.com/jmoiron/sqlx"
go get -u "github.com/zenazn/goji"
go get -u "github.com/izumin5210/ro"
go get -u "github.com/garyburd/redigo/redis"
go get -u "github.com/agatan/accessprof"
go build -o app
