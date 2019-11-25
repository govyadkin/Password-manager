# -*- coding: utf-8 -*-
from app import app, db
from flask import request, abort
from cripto import password_encrypt
import json
from halper_func import gen_password, hard_pass, check_token
from app.models import Password, User


@app.route('/admin_use')
def admin_use():
    return {"passwords": list(map(Password.printer, Password.query.all())),
            "users": list(map(User.printer, User.query.all()))}


@app.route('/signup', methods=['POST'])
def sign_up():
    data = json.loads(request.data.decode())

    users = User.query.filter_by(login=data['login']).first()

    if users is not None:
        return {"status": "Error",
                "massage": "Already exists"}

    db.session.add(User(login=data['login'], password=data['password']))
    db.session.commit()
    return {"status": "Success"}


@app.route('/signin', methods=['POST'])
def sign_in():
    data = json.loads(request.data.decode())

    users = User.query.filter_by(login=data['login']).first()

    if (users is None or
            not users.non_hash_password() == data['password']):
        return {"status": "Error",
                "massage": "Wrong login or password"}

    token = ""

    for i in range(101):
        token = gen_password(20)

        if User.query.filter_by(token=token).first() is None:
            break
        if i == 100:
            return {"status": "Error",
                    "massage": "Sorry server is heavily loaded try again later"}

    users.token = token
    hash_pass = password_encrypt(data['password'].encode(), token)
    users.password = hash_pass
    db.session.commit()
    return {"status": "Success",
            "token": token}


@app.route('/gen_pass')
def gen_pass():
    n = request.data.decode()
    if n < 8:
        return {"status": "Error",
                "massage": "Password is too short"}
        return {"status": "Success",
                "massage": gen_password(n)}


@app.route('/hard_pass')
def hard_pass_api():
    return {"status": "Success",
            "massage": hard_pass(request.data.decode())}


@app.route('/get/accounts/place', methods=['GET'])
def get_on_name_place():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    passes = user.posts.filter_by(name_place=data['name_place']).all()

    if len(passes) == 0:
        return {"status": "Error",
                "massage": "No mention of " + data['name_place']}

    return {"status": "Success",
            "result": list(map(lambda a: {"status": "Success",
                                          "login": a.login,
                                          "password": a.non_hash_password()}, passes))}


@app.route('/get/accounts/tag', methods=['GET'])
def get_on_tag():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    passes = user.posts.filter_by(tag=data['tag']).all()

    if len(passes) == 0:
        return {"status": "Error",
                "massage": "No mention of " + data['tag']}

    return {"status": "Success",
            "result": list(map(lambda a: {"name_place": a.name_place,
                                          "login": a.login,
                                          "password": a.non_hash_password()}, passes))}


@app.route('/get/accounts/all', methods=['GET'])
def get_all():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    passes = user.posts.all()

    return {"status": "Success",
            "result": list(map(Password.printer, passes))}


@app.route('/insert/password', methods=['POST'])
def insert():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    passes = user.posts.filter_by(name_place=data['name_place']).filter_by(login=data["login"]).first()

    if passes is not None:
        return {"status": "Error",
                "massage": "Already exists"}

    db.session.add(Password(name_place=data['name_place'],
                            login=data["login"],
                            password=data["password"],
                            author=user))
    db.session.commit()

    return {"status": "Success"}


@app.route('/update/password', methods=['PUT'])
def update():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    passes = user.posts.filter_by(name_place=data['name_place']).filter_by(login=data["login"]).first()

    if passes is None:
        return {"status": "Error",
                "massage": "Invalid name_place or login"}

    if not (data['new_login'] == data['login']):
        passes_new = user.posts.filter_by(name_place=data['name_place']).filter_by(login=data["new_login"]).first()
        if passes_new is not None:
            return {"status": "Error",
                    "massage": "Already exists"}

    passes.login = data['new_login']
    passes.password = password_encrypt(data['new_password'].encode(), user.non_hash_password())
    passes.tag = data['new_tag']

    db.session.commit()
    return {"status": "Success"}


@app.route('/update/user', methods=['PUT'])
def update_user():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    if not (data['new_login'] == user.login):
        user_new = User.query.filter_by(login=data["new_login"]).first()
        if user_new is not None:
            return {"status": "Error",
                    "massage": "Already exists"}

    passes = user.posts.all()

    for a in passes:
        a.password = password_encrypt(a.non_hash_password().encode(), data['new_password'])

    user.login = data['new_login']
    user.password = password_encrypt(data['new_password'].encode(), data['token'])

    db.session.commit()

    return {"status": "Success"}


@app.route('/delete/password', methods=['DELETE'])
def delete():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    passes = user.posts.filter_by(name_place=data['name_place']).filter_by(login=data['login']).first()

    if passes is None:
        return {"status": "Error",
                "massage": "Invalid name_place or login"}

    db.session.delete(passes)
    db.session.commit()
    return {"status": "Success"}


@app.route('/delete/user', methods=['DELETE'])
def delete_user():
    data = json.loads(request.data.decode())

    user = User.query.filter_by(token=data['token']).first()

    if check_token(user):
        abort(401)

    passes = user.posts.all()

    for _pass in passes:
        db.session.delete(_pass)

    db.session.delete(user)
    db.session.commit()

    return {"status": "Success"}
