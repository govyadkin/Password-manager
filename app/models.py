import json
import datetime
import hashlib
from app import db, login
from cripto import password_encrypt, password_decrypt

Active_time = 30


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(65))
    timestamp = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow)

    open_key_client = db.Column(db.LargeBinary)

    passes = db.relationship('Password', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return (datetime.datetime.utcnow() - self.timestamp) < datetime.timedelta(minutes=Active_time)

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def printer(self):
        return {"id": self.id,
                "login": self.login}

    def time_sign_in(self):
        self.timestamp = datetime.datetime.utcnow()

    def __init__(self, login, password, open_key_client):
        self.login = login
        self.set_password(password)
        self.timestamp = datetime.datetime.utcnow()
        self.open_key_client = open_key_client

    def __repr__(self):
        return json.dumps(self.printer())


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_place = db.Column(db.String(80))
    login = db.Column(db.String(120))
    password = db.Column(db.LargeBinary)
    tag = db.Column(db.String(20))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def non_hash_password(self, key):
        return password_decrypt(self.password, key).decode()

    def printer(self, key):
        return {"name_place": self.name_place,
                "login": self.login,
                "password": self.non_hash_password(key),
                "user_id": self.user_id,
                "tag": self.tag}

    def __init__(self, name_place, login, password, key, author, tag="All"):
        self.name_place = name_place
        self.login = login
        self.password = password_encrypt(password.encode(), key)
        self.tag = tag
        self.author = author

    def __repr__(self):
        return json.dumps(self.printer())
