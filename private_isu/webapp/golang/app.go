package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/garyburd/redigo/redis"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/izumin5210/ro"
	"github.com/jmoiron/sqlx"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
)

var (
	db           *sqlx.DB
	store        *gsm.MemcacheStore
	redisPool    *redis.Pool
	userStore    ro.Store
	commentStore ro.Store
)

var (
	regexpAccountName = regexp.MustCompile("\\A[0-9a-zA-Z_]{3,}\\z")
	regexpPassword    = regexp.MustCompile("\\A[0-9a-zA-Z_]{6,}\\z")
)

const (
	postsPerPage   = 20
	ISO8601_FORMAT = "2006-01-02T15:04:05-07:00"
	UploadLimit    = 10 * 1024 * 1024 // 10mb

	// CSRF Token error
	StatusUnprocessableEntity = 422
)

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []*Comment
	User         *User
	CSRFToken    string
}

func init() {
	memcacheClient := memcache.New("localhost:11211")
	store = gsm.NewMemcacheStore(memcacheClient, "isucogram_", []byte("sendagaya"))
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}

	conn := redisPool.Get()
	conn.Do("FLUSHALL")
	conn.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		comments := []*Comment{}
		err := db.Select(&comments, "SELECT * FROM comments")
		if err != nil {
			handleError(err)
			return
		}
		for _, c := range comments {
			c.CreatedAtNano = c.CreatedAt.UnixNano()
		}
		err = commentStore.Set(comments)
		if err != nil {
			handleError(err)
			return
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		users := []*User{}
		err := db.Select(&users, "SELECT * FROM users")
		if err != nil {
			handleError(err)
			return
		}
		for _, u := range users {
			u.CreatedAtNano = u.CreatedAt.UnixNano()
		}
		err = userStore.Set(users)
		if err != nil {
			handleError(err)
			return
		}
	}()

	wg.Wait()
}

func writeImage(postID int, ext string, img []byte) error {
	return ioutil.WriteFile(fmt.Sprintf("../public/image/%d.%s", postID, ext), img, 0644)
}

func tryLogin(accountName, password string) *User {
	users := []*User{}
	err := userStore.Select(&users, userStore.Query(fmt.Sprintf("accountName:%s", accountName)).Eq(0).Limit(1))
	if err != nil || len(users) == 0 {
		return nil
	}

	u := users[0]

	if u != nil && !u.IsBanned() && calculatePasshash(u.AccountName, password) == u.Passhash {
		return u
	} else if u == nil {
		return nil
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexpAccountName.MatchString(accountName) && regexpPassword.MatchString(password)
}

func digest(src string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(src)))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) *User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	var id int
	if !ok || uid == nil {
		return &User{}
	} else if v, ok := uid.(int64); ok {
		id = int(v)
	} else if v, ok := uid.(int); ok {
		id = v
	}

	u := &User{ID: id}

	err := userStore.Get(u)
	if err != nil {
		return &User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []*Post, CSRFToken string, allComments bool) ([]*Post, error) {
	var posts []*Post

	for _, p := range results {
		cnt, err := commentStore.Count(commentStore.Query("post").Eq(p.ID))
		if err != nil {
			return nil, err
		}
		p.CommentCount = cnt

		query := commentStore.Query("post").Eq(p.ID).Reverse()
		if !allComments {
			query = query.Limit(3)
		}
		var comments []*Comment
		cerr := commentStore.Select(&comments, query)
		if cerr != nil {
			return nil, cerr
		}

		for i := 0; i < len(comments); i++ {
			comments[i].User = &User{ID: comments[i].UserID}
			uerr := userStore.Get(comments[i].User)
			if uerr != nil {
				return nil, uerr
			}
		}

		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}

		p.Comments = comments

		p.User = &User{ID: p.UserID}
		perr := userStore.Get(p.User)
		if perr != nil {
			return nil, perr
		}

		p.CSRFToken = CSRFToken

		if p.User.DelFlg == 0 {
			posts = append(posts, p)
		}
		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p *Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u *User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := io.ReadFull(crand.Reader, k); err != nil {
		panic("error reading from random source: " + err.Error())
	}
	return hex.EncodeToString(k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    *User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    *User
		Flash string
	}{&User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists, err := userStore.Count(userStore.Query(fmt.Sprintf("accountName:%s", accountName)).Eq(0).Limit(1))
	if err != nil {
		handleError(err)
		return
	}

	if exists != 0 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	passhash := calculatePasshash(accountName, password)
	result, eerr := db.Exec(query, accountName, passhash)
	if eerr != nil {
		handleError(eerr)
		return
	}

	session := getSession(r)
	uid, lerr := result.LastInsertId()
	if lerr != nil {
		handleError(lerr)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)
	userStore.Set(&User{
		ID:            int(uid),
		AccountName:   accountName,
		Passhash:      passhash,
		CreatedAtNano: time.Now().UnixNano(),
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []*Post{}

	err := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC")
	if err != nil {
		handleError(err)
		return
	}

	posts, merr := makePosts(results, getCSRFToken(r), false)
	if merr != nil {
		handleError(merr)
		return
	}

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("index.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts     []*Post
		Me        *User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}

func getAccountName(c web.C, w http.ResponseWriter, r *http.Request) {
	users := []*User{}
	uerr := userStore.Select(&users, userStore.Query(fmt.Sprintf("accountName:%s", c.URLParams["accountName"])).Eq(0).Limit(1))

	if uerr != nil {
		handleError(uerr)
		return
	}

	user := users[0]

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []*Post{}

	rerr := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC", user.ID)
	if rerr != nil {
		handleError(rerr)
		return
	}

	posts, merr := makePosts(results, getCSRFToken(r), false)
	if merr != nil {
		handleError(merr)
		return
	}

	commentCount, cerr := commentStore.Count(commentStore.Query("user").GtEq(user.ID).LtEq(user.ID))
	if cerr != nil {
		handleError(cerr)
		return
	}

	postIDs := []int{}
	perr := db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if perr != nil {
		handleError(perr)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		for postID := range postIDs {
			cnt, ccerr := commentStore.Count(commentStore.Query("post").Eq(postID))
			if ccerr != nil {
				handleError(ccerr)
				return
			}
			commentedCount += cnt
		}
	}

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts          []*Post
		User           *User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             *User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		handleError(parseErr)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, terr := time.Parse(ISO8601_FORMAT, maxCreatedAt)
	if terr != nil {
		handleError(terr)
		return
	}

	results := []*Post{}
	rerr := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC", t.Format(ISO8601_FORMAT))
	if rerr != nil {
		handleError(rerr)
		return
	}

	posts, merr := makePosts(results, getCSRFToken(r), false)
	if merr != nil {
		handleError(merr)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, posts)
}

func getPostsID(c web.C, w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(c.URLParams["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []*Post{}
	rerr := db.Select(&results, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if rerr != nil {
		handleError(rerr)
		return
	}

	posts, merr := makePosts(results, getCSRFToken(r), true)
	if merr != nil {
		handleError(merr)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Post *Post
		Me   *User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	file, header, ferr := r.FormFile("file")
	if ferr != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = "jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = "png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = "gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, rerr := ioutil.ReadAll(file)
	if rerr != nil {
		handleError(rerr)
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)"
	result, eerr := db.Exec(
		query,
		me.ID,
		mime,
		r.FormValue("body"),
	)
	if eerr != nil {
		handleError(eerr)
		return
	}

	pid, lerr := result.LastInsertId()
	if lerr != nil {
		handleError(lerr)
		return
	}

	ierr := writeImage(int(pid), ext, filedata)
	if ierr != nil {
		handleError(ierr)
		return
	}

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
	return
}

func getImage(c web.C, w http.ResponseWriter, r *http.Request) {
	pidStr := c.URLParams["id"]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := &Post{}
	derr := db.Get(post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if derr != nil {
		handleError(derr)
		return
	}

	ext := c.URLParams["ext"]

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)
		_, err := w.Write(post.Imgdata)
		if err != nil {
			handleError(err)
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	postID, ierr := strconv.Atoi(r.FormValue("post_id"))
	if ierr != nil {
		fmt.Println("post_idは整数のみです")
		return
	}

	body := r.FormValue("comment")
	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	result, cerr := db.Exec(query, postID, me.ID, body)
	if cerr != nil {
		handleError(cerr)
		return
	}
	id, lerr := result.LastInsertId()
	if lerr != nil {
		handleError(lerr)
		return
	}
	crerr := commentStore.Set(&Comment{
		ID:            int(id),
		PostID:        postID,
		UserID:        me.ID,
		Comment:       body,
		CreatedAtNano: time.Now().UnixNano(),
	})
	if cerr != nil {
		handleError(crerr)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []*User{}
	err := userStore.Select(&users, userStore.Query("created_at").Gt(0).Reverse())
	if err != nil {
		handleError(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []*User
		Me        *User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	r.ParseForm()
	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	_, debug = os.LookupEnv("DEBUG")
	if debug {
		log.Println("Run in debug mode...")
	}

	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}
	redisURL := os.Getenv("ISUCONP_REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	redisPool = &redis.Pool{
		MaxIdle:     10,
		IdleTimeout: 10 * 60 * time.Second,

		Dial: func() (redis.Conn, error) {
			return redis.DialURL(redisURL)
		},
	}

	userStore, err = ro.New(redisPool.Get, &User{}, ro.WithScorers(UserScorerFuncs))
	commentStore, err = ro.New(redisPool.Get, &Comment{}, ro.WithScorers(CommentScorerFuncs))
	if err != nil {
		log.Fatalf("Failed to create comment store instance: %v", err)
	}

	goji.Get("/initialize", getInitialize)
	goji.Get("/login", getLogin)
	goji.Post("/login", postLogin)
	goji.Get("/register", getRegister)
	goji.Post("/register", postRegister)
	goji.Get("/logout", getLogout)
	goji.Get("/", getIndex)
	goji.Get(regexp.MustCompile(`^/@(?P<accountName>[a-zA-Z]+)$`), getAccountName)
	goji.Get("/posts", getPosts)
	goji.Get("/posts/:id", getPostsID)
	goji.Post("/", postIndex)
	goji.Get("/image/:id.:ext", getImage)
	goji.Post("/comment", postComment)
	goji.Get("/admin/banned", getAdminBanned)
	goji.Post("/admin/banned", postAdminBanned)
	goji.Get("/dump_images", dumpImages)
	goji.Get("/*", http.FileServer(http.Dir("../public")))
	goji.Serve()
}
