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
		articles = get_latest()
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

def add_article(article):
	article.put()
	mc_key = "%s-%d" % (article.path, article.version)
	age_set(mc_key, article)
	get_latest(update = True)
	return str(article.key().id())

def get_revisions(path):
	# return list of article revisions ordered by creation date (decending)
 	p = article_key(path)
	q = db.GqlQuery("SELECT * FROM Article WHERE ANCESTOR IS :1 ORDER BY created DESC", p)
	return q

def get_revision(path, version = None):
	# returns latest revision in the absence of a version number
	mc_key = "%s-%s" % (path, version)
	article, age = age_get(mc_key)

	if not article:
		p = article_key(path)

		if version:
			q = db.GqlQuery("SELECT * FROM Article WHERE ANCESTOR IS :1 AND version = :2", p, int(version))
		else:
			q = get_revisions(path)	
		
		article = q.get()
	
	return article 


def get_latest(update = False):
	mc_key = "latest"
	articles, age = age_get(mc_key)

	if not articles or update:
		q = db.GqlQuery("SELECT * FROM Article ORDER BY created DESC LIMIT 10")
		articles = list(q)
		age_set(mc_key, articles)

	return articles

def create_path(path):
	# NOTE: maintain path case 
	return path.replace(" ", "-")

def article_key(name = 'default'):
	return db.Key.from_path('Wiki', name)


class Article(db.Model):
	content = db.TextProperty(required = True)
	subject = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	version = db.IntegerProperty(required = True)
	author = db.StringProperty(required = True)
	path = db.StringProperty(required = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br />')
		return render_str("article.html", article = self)

	def render_summary(self):
		return render_str("summary.html", article = self)


class ViewPage(Handler):
	def get(self, path):
  		v = self.request.get('v')
  		p = create_path(path)
		r = get_revision(p, v)

  		if r:
  			self.render("article_permalink.html", user = self.user, article = r)
  		else:
  			# if logged in redirect to the edit/create page ..
			if self.user:
				self.redirect("/_edit/%s" % p)	
			else:
				# .. else go home
				# TODO: this should 404?
				self.redirect("/")	


class EditPage(Handler):
	def get(self, path):
		if not self.user:
			self.redirect("/login")

		v = self.request.get('v')
		r = get_revision(path, v)
		self.render("article_create.html", user = self.user, article = r)

	def post(self, path):
		v = 1
		r = get_revision(path)

		if r: 
			v = r.version + 1

		params = dict(path = path)
		params['author'] = self.user.name
		params['parent'] = article_key(path)
		params['subject'] = self.request.get("subject")
		params['content'] = self.request.get("content")
		params['version'] = v 

		a = Article(**params)
		add_article(a)

		self.redirect("/%s" % path)	

#### Archive

class History(Handler):
	def get(self, path):
		if not self.user:
			self.redirect("/login")

		h = get_revisions(path)
		a = h.get()
		self.render("history.html", user = self.user, article = a, history = h)

#### Lets go!

RE_URL = '([a-zA-Z0-9_\-\s]+)'

app = webapp2.WSGIApplication([ ('/', HomePage),
								('/signup', Signup), 
								('/login', Login), 
								('/logout', Logout), 
								('/_edit/'+RE_URL, EditPage), 
								('/'+RE_URL, ViewPage),
								('/_history/'+RE_URL, History)], debug=True)