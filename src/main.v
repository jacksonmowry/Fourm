module main

import vweb
import db.sqlite
import crypto.bcrypt
import rand
import math

struct App {
	vweb.Context
mut:
	user User
	db   sqlite.DB
}

struct Article {
	id        int
	title     string
	author    string
	body      string
	likes     int
	author_id int // foreign key for one->many relationship
}

struct User {
	id       int
	username string
	password string // hashed
}

struct Session {
	id            int
	session_token string
	user_id       int
}

struct Likes {
	id         int
	article_id int
	user_id    int
}

fn main() {
	db := sqlite.connect('fourm.db')!

	db.exec_none('CREATE TABLE IF NOT EXISTS articles(
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					title TEXT NOT NULL,
					author TEXT NOT NULL,
					body TEXT NOT NULL,
					likes INTEGER DEFAULT 0,
					author_id INTEGER NOT NULL,
					FOREIGN KEY (author_id) REFERENCES users(id)
			)')

	db.exec_none('CREATE TABLE IF NOT EXISTS users(
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					username TEXT NOT NULL UNIQUE,
					password TEXT NOT NULL
			)')

	db.exec_none('CREATE TABLE IF NOT EXISTS sessions(
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					session_token TEXT NOT NULL UNIQUE,
					user_id INTEGER NOT NULL,
					FOREIGN KEY (user_id) REFERENCES users(id)
			)')

	db.exec_none('CREATE TABLE IF NOT EXISTS likes(
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					article_id INTEGER,
					user_id INTEGER,
					FOREIGN KEY (article_id) REFERENCES article(id),
					FOREIGN KEY (user_id) REFERENCES users(id)
			)')

	mut app := App{
		db: db
	}
	app.serve_static('/output.css', './css/output.css')
	app.serve_static('/favicon.ico', './static/favicon.ico')
	vweb.run(app, 8080)
}

['/']
pub fn (mut app App) index() vweb.Result {
	return app.redirect('/page/1')
}

[middleware: auth_user]
['/page/:page']
pub fn (mut app App) page(page int) vweb.Result {
	max_pages := math.ceil(f64(app.num_articles()) / 10)
	mut prev := true
	mut next := true
	mut prev_page := page - 1
	mut next_page := page + 1
	if page > max_pages {
		return app.redirect('/latest')
	}
	if page == 1 {
		prev = false
	}
	if page == max_pages {
		next = false
	}
	articles := app.articles_by_page(page) or { return app.redirect('/') }

	return $vweb.html()
}

[middleware: auth_user]
['/latest']
pub fn (mut app App) latest() vweb.Result {
	article := app.latest_article() or { Article{} }
	liked := app.has_liked(article.id)
	return $vweb.html()
}

[middleware: auth_user]
['/article/:id']
pub fn (mut app App) article(id int) vweb.Result {
	article := app.single_article(id) or { return app.not_found() }
	liked := app.has_liked(article.id)
	return $vweb.html()
}

[middleware: auth_user]
['/author/:name']
pub fn (mut app App) author(name string) vweb.Result {
	articles := app.get_by_author(name) or { []Article{} }
	return $vweb.html()
}

[middleware: auth_user]
['/new']
pub fn (mut app App) new() vweb.Result {
	if app.user == User{} {
		return app.redirect('/#login')
	}
	return $vweb.html()
}

[middleware: auth_user]
['/new_article'; post]
pub fn (mut app App) new_article(title string, body string) vweb.Result {
	if app.user == User{} {
		return app.redirect('/login')
	}
	if title == '' || body == '' {
		return app.redirect('/new')
	}

	app.db.exec_param_many('INSERT INTO articles (title, author, body, likes, author_id) VALUES (?, ?, ?, ?, ?)',
		[title, app.user.username, body, '0', app.user.id.str()]) or { return app.text(err.str()) }

	return app.redirect('/')
}

[middleware: auth_user]
['/signup_form'; post]
pub fn (mut app App) signup_form(username string, password string) vweb.Result {
	if username == '' || password == '' {
		return app.redirect('${app.get_header('referer')}#signup')
	}

	hashed := bcrypt.generate_from_password(password.bytes(), 10) or { return app.text(err.str()) }

	app.db.exec_param_many('INSERT INTO users (username, password) VALUES (?, ?)', [
		username,
		hashed,
	]) or { return app.text(err.str()) }
	if app.db.get_affected_rows_count() == 0 {
		return app.redirect('${app.get_header('referer')}#taken')
	}
	row := app.db.exec_one('SELECT id from users ORDER BY id DESC') or {
		return app.text(err.str())
	}

	session_token := rand.uuid_v4()
	app.db.exec_param_many('INSERT INTO sessions (session_token, user_id) VALUES (?, ?)',
		[
		session_token,
		row.vals[0],
	]) or { return app.text(err.str()) }

	app.set_cookie(name: 'session_token', value: session_token)

	referer := app.get_header('referer')

	return app.redirect(referer)
}

[middleware: auth_user]
['/login_form'; post]
pub fn (mut app App) login_form(username string, password string) vweb.Result {
	if username == '' || password == '' {
		return app.redirect('${app.get_header('referer')}#wrong')
	}

	user := app.db.exec_param('SELECT * FROM users where username = ? LIMIT 1', username) or {
		return app.text(err.str())
	}
	if user.len == 0 {
		return app.redirect('${app.get_header('referer')}#wrong')
	}

	bcrypt.compare_hash_and_password(password.bytes(), user[0].vals[2].bytes()) or {
		return app.redirect('${app.get_header('referer')}#wrong')
	}

	session_token := rand.uuid_v4()

	app.db.exec_param_many('INSERT INTO sessions (session_token, user_id) VALUES (?, ?)',
		[
		session_token,
		user[0].vals[0],
	]) or { return app.redirect('/#wrong') }

	app.set_cookie(name: 'session_token', value: session_token)

	referer := app.get_header('referer')

	return app.redirect(referer)
}

['/signout']
pub fn (mut app App) signout() vweb.Result {
	session_token := app.get_cookie('session_token') or { return app.redirect('/') }

	app.db.exec_param('DELETE FROM sessions where session_token = ?', session_token) or {
		return app.redirect('/')
	}

	app.set_cookie(name: 'session_token', value: '')

	return app.redirect('/')
}

[middleware: auth_user]
['/upvote/:id']
pub fn (mut app App) upvote(id int) vweb.Result {
	if app.user == User{} {
		return app.redirect('${app.get_header('referer')}#login')
	}
	like := app.db.exec_param_many('SELECT * FROM likes where article_id = ? AND user_id =?',
		[
		id.str(),
		app.user.id.str(),
	]) or { return app.text(err.str()) }

	if like.len == 0 {
		app.db.exec_param_many('INSERT INTO likes (article_id, user_id) VALUES (?, ?)',
			[
			id.str(),
			app.user.id.str(),
		]) or { return app.text(err.str()) }
		app.db.exec_param('UPDATE articles SET likes = likes + 1 WHERE id = ?', id.str()) or {
			return app.text(err.str())
		}
	} else {
		app.db.exec_param_many('DELETE FROM likes where article_id = ? AND user_id = ?',
			[
			id.str(),
			app.user.id.str(),
		]) or { return app.text(err.str()) }
		app.db.exec_param('UPDATE articles SET likes = likes - 1 WHERE id = ?', id.str()) or {
			return app.text(err.str())
		}
	}

	return app.redirect(app.get_header('referer'))
}

fn (app App) all_articles() ?[]Article {
	rows := app.db.exec('SELECT * FROM articles ORDER BY id DESC') or { return none }
	articles := convert_to_article(rows) or { []Article{} }
	return articles
}

fn (app App) latest_article() ?Article {
	row := app.db.exec_one('SELECT * FROM articles ORDER BY id DESC LIMIT 1') or { return none }
	article := convert_to_article([row]) or { return none }
	return article[0]
}

fn (app App) single_article(id int) ?Article {
	row := app.db.exec_param('SELECT * FROM articles where id == ?', id.str()) or { return none }
	article := convert_to_article(row) or { return none }
	return article[0]
}

fn (app App) articles_by_page(page int) ?[]Article {
	offset := (page - 1) * 10
	rows := app.db.exec_param('SELECT * FROM articles ORDER BY id DESC LIMIT 10 OFFSET ?',
		offset.str()) or { return none }
	articles := convert_to_article(rows) or { return none }
	return articles
}

fn (app App) get_by_author(author string) ?[]Article {
	rows := app.db.exec_param('SELECT * FROM articles WHERE author = ?', author) or { return none }
	articles := convert_to_article(rows) or { return none }
	return articles
}

fn (app App) has_liked(id int) bool {
	row := app.db.exec_param_many('SELECT * FROM likes where user_id = ? AND article_id = ? LIMIT 1',
		[
		app.user.id.str(),
		id.str(),
	]) or { return false }

	if row.len == 0 {
		return false
	} else {
		return true
	}
}

fn convert_to_article(rows []sqlite.Row) ?[]Article {
	if rows.len == 0 {
		return none
	}
	mut articles := []Article{}
	for row in rows {
		temp_article := Article{
			id: row.vals[0].int()
			title: row.vals[1]
			author: row.vals[2]
			body: row.vals[3]
			likes: row.vals[4].int()
			author_id: row.vals[5].int()
		}
		articles << temp_article
	}

	return articles
}

fn convert_to_user(rows []sqlite.Row) ?[]User {
	if rows.len == 0 {
		return none
	}
	mut users := []User{}
	for row in rows {
		temp_user := User{
			id: row.vals[3].int()
			username: row.vals[4]
		}
		users << temp_user
	}
	return users
}

fn (app App) num_articles() int {
	count := app.db.q_int('SELECT COUNT(*) FROM articles') or { 0 }
	return count
}

fn (mut app App) auth_user() bool {
	session_token := app.get_cookie('session_token') or { return true }
	row := app.db.exec_param('SELECT * FROM sessions LEFT JOIN users ON sessions.user_id = users.id where session_token = ? LIMIT 1',
		session_token) or { return true }
	user := convert_to_user(row) or { return true }
	app.user = user[0]
	return true
}
