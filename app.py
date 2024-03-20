import os
import smtplib
from datetime import timedelta, datetime
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from forms import CommentForm, ContactForm, CreatePostForm

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
app.app_context().push()
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)

login_manager = LoginManager()

login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


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
    tag = db.Column(db.String(250), nullable=False)
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


def format_time_elapsed(date_string):
    # Convert date string to datetime object
    date_time_obj = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
    # Calculate the time elapsed from the given date to the current date
    time_elapsed = datetime.now() - date_time_obj
    # Convert time elapsed to minutes
    minutes_elapsed = int(time_elapsed.total_seconds() / 60)
    # Return the formatted HTML string
    return minutes_elapsed


def format_date(date_string):
    # Convert date string to datetime object
    date_time_obj = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
    # Return the formatted HTML string
    return date_string[:10]


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,
                           format_time_elapsed=format_time_elapsed,format_date=format_date)


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
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('rememberMe') == 'on'  # Convert to boolean
        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=remember_me)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Incorrect username or incorrect password.', 'error')
                return redirect(url_for('login'))
        else:
            flash('Incorrect username or incorrect password.', 'error')
            return redirect(url_for('login'))

    return render_template("login.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if the password and confirm_password match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        # Check if the email is already registered
        existing_user_mail = User.query.filter_by(email=email).first()
        if existing_user_mail:
            flash('Email already exists.', 'error')
            return redirect(url_for('register'))
        existing_user = User.query.filter_by(user=username).first()
        if existing_user:
            flash('Email already exists.', 'error')
            return redirect(url_for('register'))

        # Create a new user
        new_user = User(email=email, username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


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


# Route for creating a new blog post
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        title = request.form.get('title')
        subtitle = request.form.get('subtitle')
        tag = request.form.get('tag')
        body = request.form.get('body')
        img_url = request.form.get('img_url')
        # Assuming you have a logged-in user and you get the poster_id somehow
        poster_id = current_user.id  # Replace with the actual poster_id

        # Create a new BlogPost instance
        new_post = BlogPost(
            poster_id=poster_id,
            title=title,
            subtitle=subtitle,
            tag=tag,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            body=body,
            img_url=img_url
        )
        # Add the new post to the database
        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for('get_all_posts'))  # Redirect to the create_post route to clear the form

    return render_template('create_post.html')


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

    return render_template("create_post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@addminonly
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
