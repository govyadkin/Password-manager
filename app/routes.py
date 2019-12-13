# -*- coding: utf-8 -*-
import json
from flask import request
from app import app, db
from halper_func import gen_password, hard_pass, check_input, delete_user
from app.models import Password, User
from flask_login import current_user, login_user, logout_user, login_required
from cripto import password_encrypt
import rsa


@app.route('/login')
def login():
    return {'status': 'Error',
            'massage': 'Authenticate'}, 401


# @app.route('/admin_use')
# def admin_use():
#     db.drop_all()
#     db.create_all()
#     u1 = User(login='MishaGo', password='Qwerty123456')
#     u = User(login='Mishal', password='Qwerty123456')
#     db.session.add(u)
#     db.session.add(u1)
#     db.session.add(
#         Password(name_place='bmstu.ru', login='MishaGo', password='Qwerty123456', key='Qwerty123456', tag='All',
#                  author=u))
#     db.session.add(
#         Password(name_place='bmstu.ru', login='Misha', password='Qwerty123456', key='Qwerty123456', tag='All',
#                  author=u))
#     db.session.commit()
#     return {'passwords': list(map(lambda a: {'name_place': a.name_place,
#                                              'login': a.login,
#                                              'user_id': a.user_id}, Password.query.all())),
#             'users': list(map(lambda a: {'login': a.login}, User.query.all()))}


@app.route('/', methods=['GET'])
def helloworld():
    return "hello, world"


@app.route('/user/signup', methods=['POST'])
def sign_up():
    if current_user.is_authenticated:
        logout_user()
    db.drop_all()
    db.create_all()
    data = json.loads(request.data.decode())

    ch_in = check_input(data, ['login', 'password', 'open_key_client'], current_user)
    if ch_in['status']:
        return ch_in["massage"], ch_in['num_error']

    if len(data['password']) < 8:
        return {'status': 'Error',
                'massage': 'Unacceptable length password'}, 411

    if User.query.filter_by(login=data['login']).first() is not None:
        return {'status': 'Error',
                'massage': 'Already exists'}, 422

    db.session.add(
        User(login=data['login'], password=data['password'], open_key_client=data['open_key_client'].encode()))
    db.session.commit()
    piv = rsa.PrivateKey.load_pkcs1(app.config['SECRET_KEY'].encode())
    return {'status': 'Success',
            'open_key_server': rsa.PublicKey(piv.n, piv.e).save_pkcs1('PEM').decode()}


@app.route('/user/sign_in', methods=['PUT'])
def sign_in():
    if current_user.is_authenticated:
        return {'status': 'Success'}

    data = json.loads(rsa.decrypt(request.data, rsa.PrivateKey.load_pkcs1(app.config['SECRET_KEY'].encode())).decode())

    ch_in = check_input(data, ['login', 'password'], current_user)
    if ch_in['status']:
        return ch_in["massage"], ch_in['num_error']

    user = User.query.filter_by(login=data['login']).first()

    if (user is None or
            not user.check_password(data['password'])):
        return {'status': 'Error',
                'massage': 'Wrong login or password'}, 422

    login_user(user)

    user.time_sign_in()

    db.session.commit()
    return {'status': 'Success'}


@app.route('/user/sign_out')
def sign_out():
    logout_user()
    return {'status': 'Success'}


@app.route('/password/gen_pass')
def gen_password_api():
    data = json.loads(request.data.decode())

    ch_in = check_input(data, ['size'], current_user)
    if ch_in['status']:
        return ch_in["massage"], ch_in['num_error']

    if data['size'] < 8:
        return {'status': 'Error',
                'massage': 'Password is too short'}, 422
    return {'status': 'Success',
            'massage': gen_password(data['size'])}


@app.route('/password/hard_pass')
def hard_password_api():
    data = json.loads(request.data.decode())

    ch_in = check_input(data, ['password'], current_user)
    if ch_in['status']:
        return ch_in["massage"], ch_in['num_error']

    return {'status': 'Success',
            'massage': hard_pass(data['password'])}


@app.route('/password/get/<section>', methods=['GET'])
@login_required
def get_on_section(section):
    data = json.loads(rsa.decrypt(request.data, app.config['SECRET_KEY']).decode())

    ch = check_input(data, ['key', section], current_user)
    if ch['status']:
        return ch["massage"], ch['num_error']

    passes = current_user.passes

    if section == 'name_place':
        passes = passes.filter_by(name_place=data['name_place']).all()
    elif section == 'tag':
        passes = passes.filter_by(tag=data['tag']).all()
    elif section == 'all':
        passes = passes.all()
    else:
        return {'status': 'Error',
                'massage': 'Invalid section'}, 404

    db.session.commit()
    return rsa.encrypt(json.dumps({'status': 'Success',
                                   'result': list(map(lambda a: {'name_place': a.name_place,
                                                                 'login': a.login,
                                                                 'password': a.non_hash_password(data['key'])},
                                                      passes))}).encode(), current_user.open_key_client)


@app.route('/password/insert', methods=['POST'])
@login_required
def insert_password():
    data = json.loads(rsa.decrypt(request.data, app.config['SECRET_KEY']).decode())

    ch = check_input(data, ['key', 'name_place', 'login', 'password'], current_user)
    if ch['status']:
        return ch["massage"], ch['num_error']

    passes = current_user.passes \
        .filter_by(name_place=data['name_place']) \
        .filter_by(login=data['login']).first()

    if passes is not None:
        return {'status': 'Error',
                'massage': 'Already exists'}, 422

    password = Password(name_place=data['name_place'],
                        login=data['login'],
                        password=data['password'],
                        key=data['key'],
                        author=current_user)

    if 'tag' in data and data['tag'] is '':
        password.tag = data['tag']

    db.session.add(password)
    db.session.commit()

    return {'status': 'Success'}


@app.route('/password/update', methods=['PUT'])
@login_required
def update_password_api():
    data = json.loads(rsa.decrypt(request.data, app.config['SECRET_KEY']).decode())

    ch = check_input(data, ['name_place', 'login', 'key'], current_user)
    if ch['status']:
        return ch["massage"], ch['num_error']

    passes = current_user.passes \
        .filter_by(name_place=data['name_place']) \
        .filter_by(login=data['login']).first()

    if passes is None:
        return {'status': 'Error',
                'massage': 'Invalid name_place or login'}, 422

    if 'new_login' in data:
        if not (data['new_login'] == data['login']):
            passes_new = current_user.passes \
                .filter_by(name_place=data['name_place']) \
                .filter_by(login=data['new_login']).first()
            if passes_new is not None:
                return {'status': 'Error',
                        'massage': 'Already exists this login'}, 422
        passes.login = data['new_login']

    if 'new_password' in data:
        passes.password = password_encrypt(data['new_password'].encode(), data['key'])

    if 'new_tag' in data:
        passes.tag = data['new_tag']

    db.session.commit()
    return {'status': 'Success'}


@app.route('/user/update', methods=['PUT'])
@login_required
def update_user_api():
    data = json.loads(rsa.decrypt(request.data, app.config['SECRET_KEY']).decode())

    ch = check_input(data, ['key'], current_user)
    if ch['status']:
        return ch["massage"], ch['num_error']

    if 'new_login' in data:
        if data['new_login'] is '':
            return {'status': 'Error',
                    'massage': 'Unacceptable length new_login'}, 411

        if not (data['new_login'] == current_user.login):
            user_new = User.query.filter_by(login=data['new_login']).first()
            if user_new is not None:
                return {'status': 'Error',
                        'massage': 'Already exists this login'}, 422
            current_user.login = data['new_login']

    if 'new_password' in data:
        if len(data['new_password']) < 8:
            return {'status': 'Error',
                    'massage': 'Unacceptable length new_login'}, 411

        passes = current_user.passes.all()

        for a in passes:
            a.password = password_encrypt(a.non_hash_password().encode(), data['new_password'])

        current_user.set_password(data['new_password'])

    db.session.commit()

    return {'status': 'Success'}


@app.route('/delete/password', methods=['DELETE'])
@login_required
def delete_password_api():
    data = json.loads(request.data.decode())

    ch = check_input(data, ['name_place', 'login'], current_user)
    if ch['status']:
        return ch["massage"], ch['num_error']

    passes = current_user.passes \
        .filter_by(name_place=data['name_place']) \
        .filter_by(login=data['login']).first()

    if passes is None:
        return {'status': 'Error',
                'massage': 'Invalid name_place or login'}, 422

    db.session.delete(passes)
    db.session.commit()
    return {'status': 'Success'}


@app.route('/delete/user', methods=['DELETE'])
@login_required
def delete_user_api():
    delete_user(current_user)
    return {'status': 'Success'}
