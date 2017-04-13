#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import cgi
import logging
import webapp2
import jinja2
import random
import string
import hashlib
import hmac
import json
import time
from string import letters

from google.appengine.api import memcache
from google.appengine.ext import db

templates = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), autoescape = True)


#### utils functions

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


#### Base handler class

class Handler(webapp2.RequestHandler):
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_cookie('user_id')
		self.user = uid and User.get_by_id(int(uid))

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)
	
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_cookie(self, name, value):
		cookie_val = make_secure_value(value)
		self.response.headers.add_header('Set-Cookie', str('%s=%s; Path=/' % (name, cookie_val)))

	def read_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_cookie(cookie_val)

	def login(self, user):
		self.set_cookie('user_id', str(user.key().id()))  

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')  


#### Homepage

class HomePage(Handler):
	def get(self):
		q = get_latest()
  		articles = list(q)
		return self.render("wiki.html", articles = articles, user = self.user)


#### User management 

RE_USER = "^[a-zA-Z0-9_-]{3,20}$"
RE_PASS = "^.{3,20}$"
RE_MAIL = "[\S]+@[\S]+.[\S]+$"

secret = "qwdc456&d^"


def make_secure_value(val):
	return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_cookie(value):
	val = value.split("|")[0]
	if value == make_secure_value(val): 
		return val

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)


class User(db.Model):
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	name = db.StringProperty(required = True)

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(name = name, pw_hash = pw_hash, email = email)


class Signup(Handler):
	def get(self):
		return self.render("signup.html")

	def post(self):
		has_errors = False
		self.username = cgi.escape(self.request.get('username'))
		self.password = cgi.escape(self.request.get('password'))
		self.verify = cgi.escape(self.request.get('verify'))
		self.email = cgi.escape(self.request.get('email'))
		params = dict(username = self.username, email = self.email)

		if not re.match(RE_USER, self.username):
			params['err_user'] = 'Invalid username'
			has_errors = True
		if not re.match(RE_PASS, self.password):
			params['err_pass'] = 'Invalid password'
			has_errors = True
		if self.verify != self.password:
			params['err_verify'] = 'Passwords must match'
			has_errors = True
		if self.email and not re.match(RE_MAIL, self.email):
			params['err_email'] = 'Invalid email'
			has_errors = True

		if has_errors:
			self.render("signup.html", **params)
		else:
			self.success()

	def success(self):
		u = User.by_name(self.username)
		if u:
			self.render('signup.html', err_user = "Username already exists")
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			self.redirect('/')


class Login(Handler):
	def get(self):
		return self.render("login.html")

	def post(self):
		username = cgi.escape(self.request.get('username'))
		password = cgi.escape(self.request.get('password'))

		u = User.by_name(username)
		if u and valid_pw(username, password, u.pw_hash):
			self.login(u)
			self.redirect("/")
		else:
			self.render("login.html", error = "Invalid login")


class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect("/")


#### Wiki management

def age_set(key, val):
	# add item AND time to cache
	memcache.delete(key) # explicitly delete key;
	memcache.set(key,(val, time.time()))

def age_get(key):
	# get item and time from cache
	r = memcache.get(key)

	if r:
		val, save_time = r
		age = time.time() - int(save_time)
	else:
		val, age = None, 0

	return val, age

def create_revision(article):
	q = get_revisions(article)
	l = len(list(q))
	r = Revision(version = l + 1, parent = article.key(), content = article.content,subject = article.subject, author = article.author, url = article.url)
	r.put()
	return str(r.key().id())

def get_revision(article, version):
	q = db.GqlQuery("SELECT * FROM Revision WHERE ANCESTOR IS :1 AND version = :2", article, int(version))
	return q

def get_revisions(article):
	q = db.GqlQuery("SELECT * FROM Revision WHERE ANCESTOR IS :1 ORDER BY created DESC", article)
	return q

def add_article(article):
	article.put()
	# create revision
	create_revision(article)
	# update the cache
	mc_key = "ART_"+article.url
	age_set(mc_key, article)
	get_latest(update = True) 
	return str(article.key().id())

def get_article(url):
	mc_key = "ART_"+url
	article, age = age_get(mc_key)

	if not article:
		p = Wiki.get_or_insert('wiki', name='Wiki')
		q = db.GqlQuery("SELECT * FROM Article WHERE ANCESTOR IS :1 AND url = :2", p, url)
  		article = q.get()
  		age_set(mc_key, article)

  	return article

def get_latest(update = False):
	mc_key = "ARTS"
	articles, age = age_get(mc_key)

	if not articles or update:
		p = Wiki.get_or_insert('wiki', name='Wiki')
		q = db.GqlQuery("SELECT * FROM Article WHERE ANCESTOR IS :1 ORDER BY created DESC", p)
		articles = list(q)
		age_set(mc_key, articles)

  	return articles

def create_url(s):
	return s.replace(" ", "-")


class Wiki(db.Model):
    name = db.StringProperty()


class Article(db.Model):
	content = db.TextProperty(required = True)
	subject = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	author = db.StringProperty(required = True)
	url = db.StringProperty(required = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br />')
		return render_str("article.html", article = self)


class Revision(Article):
	version = db.IntegerProperty()

	def render_summary(self):
		return render_str("summary.html", article = self)

	def _render_time(self):
		return int(time.mktime(self.created.timetuple()))


class ViewPage(Handler):
	def get(self, url):
  		a = get_article(url)
  		v = self.request.get('v')
		if a: 
			if v:
				a = get_revision(a, v).get()
			self.render("article_permalink.html", user = self.user, article = a)
		else:
			# if logged in redirect to the edit page
			if self.user:
				new_url = create_url(url)
				self.redirect("/_edit/%s" % new_url)
			else:
				# else go home
				# TODO: this should 404 
				self.redirect("/")


class EditPage(Handler):
	def get(self, url):
		if not self.user:
			self.redirect("/login")
		
		# edit/create page
		a = get_article(url)
		self.render("article_create.html", user = self.user, article = a)


	def post(self, url):
		content = self.request.get("content")
		subject = self.request.get("subject")
		a = get_article(url)

		if a:
			# update
			a.content = content
 			a.subject = subject
		else:
			# create new
			p = Wiki.get_or_insert('wiki', name='Wiki')
			a = Article(parent = p, url = url, subject = subject, content = content, author = self.user.name)
		
		add_article(a)
		self.redirect("/%s" % url)	

#### Archive

class History(Handler):
	def get(self, url):
		if not self.user:
			self.redirect("/login")

		a = get_article(url)
		q = get_revisions(a)
		self.render("history.html", user = self.user, article = a, history = q)

#### Lets go!

RE_URL = '([a-zA-Z0-9_\-\s]+)'

app = webapp2.WSGIApplication([ ('/', HomePage),
								('/signup', Signup), 
								('/login', Login), 
								('/logout', Logout), 
								('/_edit/'+RE_URL, EditPage), 
								('/'+RE_URL, ViewPage),
								('/_history/'+RE_URL, History)], debug=True)