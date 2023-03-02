import os
import smtplib
from datetime import date
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ContactForm

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
app.app_context().push()
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)

login_manager = LoginManager()

login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

csrf = CSRFProtect()
csrf.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CONFIGURE TABLES
class User(db.Model, UserMixin, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250))
    username = db.Column(db.String(250))
    blog_posts = relationship("BlogPost", backref="auther")
    comments = relationship("Comment", backref="comment_auther")
    messages = relationship("Message", backref="message_auther")


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text(), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    body = db.Column(db.Text(), nullable=False)
    blog_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    blog_post = relationship("BlogPost", backref="comments")


class Message(db.Model, Base):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    name = db.Column(db.String(250), nullable=False)
    username = db.Column(db.String(250), nullable=False)
    phone = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    message = db.Column(db.Text(), nullable=False)

    def __repr__(self):
        return f"{self.name} {self.phone} {self.email} {self.message}"


def sendmail(msg):
    """sends a mail for a specific person """
    username = "anonymous"
    poster_id = None
    my_email = "motrappentesting@gmail.com"
    my_pass = "vhtmwnwwdhgqidmv"
    receiver = "meen79508@gmail.com"
    connection = smtplib.SMTP("smtp.gmail.com")
    connection.starttls()
    connection.login(user=my_email, password=my_pass)
    connection.sendmail(
        from_addr=my_email,
        to_addrs=receiver,
        msg=f"Subject: hello bro , \n\n this is an automated message from : {msg['name']} \n number: {msg['phone']}"
            f" \n email: {msg['email']}\n msg: {msg['message']} "

    )
    if current_user.is_authenticated:
        username = current_user.username
        poster_id = current_user.id
    message = Message(name=msg['name'], username=username, phone=msg['phone'],
                      email=msg['email'], message=msg['message'], poster_id=poster_id)

    db.session.add(message)
    db.session.commit()
    connection.close()


# db.drop_all()
# db.create_all()


def addminonly(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            is_admin = current_user.id == 1
            if not is_admin:
                flash("You are not authorized to access this page")
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    return decorated_function


def logged_in(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('get_all_posts'))
        return func(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    admin = False

    try:
        name = current_user.username
        if current_user.id == 1:
            admin = True
    except:
        name = 'annonymous'
    return render_template("index.html", Name=name, all_posts=posts, logged_in=current_user.is_authenticated,
                           admin=admin)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.filter_by(id=post_id).first()
    form = CommentForm(request.form)
    comments = Comment.query.filter_by(blog_post_id=post_id).all()

    if request.method == 'POST':
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash('You need to be logged in to comment.')
                return redirect(url_for('login'))
            comment = Comment(body=form.body.data, poster_id=current_user.id, blog_post_id=post_id)
            db.session.add(comment)
            db.session.commit()
            flash('Thanks for commenting!')
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('Error: Empty comment.')
            return render_template('post.html', form=form, post=requested_post, comments=comments)

    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route('/login', methods=['GET', 'POST'])
@logged_in
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.replace(" ", "")).first()
            if user:
                if check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('get_all_posts'))
                else:
                    flash('Error: Invalid username or password.')
                    return render_template('login.html', form=form)
            else:
                flash('Error: Invalid username or password.')
                return render_template('login.html', form=form)
        else:
            flash('Error: All fields are required.')
            return render_template('login.html', form=form)
    return render_template("login.html", form=form)


@app.route('/register', methods=['GET', 'POST'])
@logged_in
def register():
    if request.method == 'POST':
        form = RegisterForm(request.form)
        if form.validate():
            if User.query.filter_by(email=form.email.data).first():
                flash('Email address already registered.')
                return redirect(url_for('register'))
            user = User()
            user.username = form.username.data.replace(" ", "")
            user.email = form.email.data.replace(" ", "")
            user.password = generate_password_hash(form.password.data)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('get_all_posts', Name=current_user.username))
        else:
            return render_template('register.html', form=form)
    form = RegisterForm()
    return render_template("register.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


success = False


@app.route("/contact", methods=["GET", "POST"])
def contact():
    global success
    if request.method == 'POST':
        form = ContactForm(request.form)
        if form.validate():
            print(form)
            if success:
                return render_template("contact.html", success=success, form=form)
            data = {
                'name': form.name.data,
                'email': form.email.data,
                'phone': form.phone_number.data,
                'message': form.message.data,
            }
            print(data)
            sendmail(data)
            event = True
            success = event
            return render_template("contact.html", msg_sent=event, form=form)
        else:
            return render_template("contact.html", form=form, success=success)


    else:
        form = ContactForm()
        success = False
        return render_template("contact.html", form=form, success=success)


@app.route("/new-post", methods=['GET', 'POST'])
@addminonly
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            poster_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")

        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@addminonly
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@addminonly
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
