from app import db
from cripto import password_encrypt, password_decrypt
from datetime import datetime
import json
from halper_func import gen_password


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(120), unique=True)
    password = db.Column(db.Binary)
    token = db.Column(db.String(80), unique=True)

    timestamp = db.Column(db.DateTime, onupdate=datetime.utcnow)

    posts = db.relationship('Password', backref='author', lazy='dynamic')

    def non_hash_password(self):
        return password_decrypt(self.password, self.token).decode()

    def printer(self):
        return {"id": self.id,
                "login": self.login,
                "password": self.non_hash_password(),
                "token": self.token}

    def __init__(self, login, password):
        self.login = login
        self.token = gen_password(20)
        self.password = password_encrypt(password.encode(), self.token)
        self.timestamp = datetime.utcnow()

    def __repr__(self):
        return json.dumps(self.printer())


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_place = db.Column(db.String(80))
    login = db.Column(db.String(120))
    password = db.Column(db.Binary)
    tag = db.Column(db.String(80), default="ALL")

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def non_hash_password(self):
        return password_decrypt(self.password, self.author.non_hash_password()).decode()

    def printer(self):
        return {"name_place": self.name_place,
                "login": self.login,
                "password": self.non_hash_password(),
                "user_id": self.user_id,
                "tag": self.tag}

    def __init__(self, name_place, login, password, tag, author):
        self.name_place = name_place
        self.login = login
        self.password = password_encrypt(password.encode(), author.non_hash_password())
        self.tag = tag
        self.author = author

    def __repr__(self):
        return json.dumps(self.printer())
