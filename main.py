from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, Session
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateNewUser, LoginUser, CommentForm
from flask_gravatar import Gravatar
from sqlalchemy import create_engine
from functools import wraps
from flask import abort
from sqlalchemy.ext.declarative import declarative_base
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def admin(function):
    @wraps(function)
    def fun(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403)
    return fun


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

engine = create_engine(os.getenv("DATABASE_URL", "sqlite:///blog.db"))
session = Session(engine)


@login_manager.user_loader
def get_user(id):
    return User.query.get(int(id))


Base = declarative_base()


class User(UserMixin, db.Model, Base):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), nullable=False)
    blogs = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author_comments")


with app.app_context():

    class BlogPost(db.Model, Base):
        __tablename__ = "blog_posts"
        id = db.Column(db.Integer, primary_key=True)
        author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
        author = relationship("User", back_populates="blogs")
        comments = relationship("Comment", back_populates="blogs_comments")
        title = db.Column(db.String(250), unique=True, nullable=False)
        subtitle = db.Column(db.String(250), nullable=False)
        date = db.Column(db.String(250), nullable=False)
        body = db.Column(db.Text, nullable=False)
        img_url = db.Column(db.String(250), nullable=False)

    class Comment(db.Model, Base):
        __tablename__ = "comments"
        id = db.Column(db.Integer, primary_key=True)
        author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
        blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
        author_comments = relationship("User", back_populates="comments")
        blogs_comments = relationship("BlogPost", back_populates="comments")
        text = db.Column(db.Text, nullable=False)

# db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    is_admin = False
    admin = User.query.filter_by(id=1).first()
    if current_user == admin:
        is_admin = True
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, admin=is_admin)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = CreateNewUser()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You already signed up with that email! Try to login instead!", category='error')
            return redirect(url_for('login'))
        else:
            user = User(
                name=form.name.data,
                password=generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8),
                email=form.email.data,
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash(message="Password is invalid, try again!", category="error")
                return redirect(url_for('login'))
        else:
            flash(message="There is no user with that email, try again!", category="error")
            return redirect(url_for('login'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    is_admin = False
    admin = User.query.filter_by(id=1).first()
    if current_user == admin:
        is_admin = True
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        comment = Comment(
            text=form.user_comment.data,
            author_comments=current_user,
            blogs_comments=requested_post,
        )
        flash(message="To leave a comment, you need to login first!", category="error")
        if not current_user.is_authenticated:
            redirect(url_for('login'))
        db.session.add(comment)
        db.session.commit()
        form.user_comment.data = ''
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, admin=is_admin, form=form)



@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['GET', 'POST'])
@admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(port=5000)
