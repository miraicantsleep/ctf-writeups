import os
import pickle
from flask import Flask, request, render_template, session
from flask_sqlalchemy import SQLAlchemy
from utils import *
import uuid
from base64 import b64encode, b64decode

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.secret_key = os.environ.get("SECRET_KEY", "love")
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)


class UserSession:
    def __init__(self, username) -> None:
        self.uuid = str(uuid.uuid1())
        self.username = username

    def __str__(self) -> str:
        return f"{self.uuid}-{self.username}"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or password != user.password:
        return "<script>alert('Login failed'); location.replace('/login');</script>"

    session["auth"] = True
    session["user"] = b64encode(pickle.dumps(UserSession(username))).decode()

    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get("username")
    password = request.form.get("password")
    print(username, password)

    exists = User.query.filter_by(username=username).first()
    if exists:
        return "<script>alert('Username already exists'); location.replace('/register');</script>"

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return "<script>alert('User created'); location.replace('/login');</script>"


@app.route("/", methods=["GET"])
@must_authenticated
def home():
    return render_template("index.html")


@app.route("/profile", methods=["GET"])
@must_authenticated
def profile():
    user = pickle.loads(b64decode(session.get("user").encode()))

    return render_template("profile.html", user=user)


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(
        host=os.environ.get("HOST", "localhost"),
        port=os.environ.get("PORT", 5000),
        debug=os.environ.get("DEBUG", "True") == "True",
    )
