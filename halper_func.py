import random
import datetime
from math import log2


def hard_pass(password):
    n = 0
    flag = [True, True, True, True, True, True]
    for i in password:
        if flag[0] and '9' >= i >= '0':
            n += 10
            flag[0] = False
        elif flag[1] and 'A' >= i >= 'Z':
            n += 26
            flag[1] = False
        elif flag[2] and 'a' >= i >= 'z':
            n += 26
            flag[2] = False
        elif flag[3] and chr(96) >= i >= '[' and '~' >= i >= '{':
            n += 10
            flag[3] = False
        elif flag[4] and '@' >= i >= ':':
            n += 7
            flag[4] = False
        elif flag[5] and '/' >= i >= ' ':
            n += 16
            flag[5] = False
    return len(password) * log2(n)


def gen_password(n):
    password = (chr(random.randint(48, 57)) +
                chr(random.randint(32, 47)) +
                chr(random.randint(58, 64)) +
                chr(random.randint(65, 90)) +
                chr(random.randint(93, 96)) +
                chr(random.randint(97, 122)) +
                chr(random.randint(123, 126)))
    while n > len(password):
        i = random.randint(32, 126)
        if i == 34 or i == 92:
            i += 1
        password += chr(i)
    return ''.join(random.sample(password, len(password)))


def check_input(data, names, user):
    for name in names:
        if data[name] is str and data[name] is '':
            return {'status': True,
                    "massage": {'status': 'Error',
                                'massage': 'Unacceptable length ' + name},
                    'num_error': 411}

        if name not in data:
            return {'status': True,
                    "massage": {'status': 'Error',
                                'massage': 'not found field ' + name},
                    'num_error': 400}

    if 'key' in names and not user.check_password(data['key']):
        return {'status': True,
                "massage": {'status': 'Error',
                            'massage': 'Invalid key'},
                'num_error': 422}

    return {'status': False}


from app import db


def delete_user(user):
    passes = user.passes.all()

    for _pass in passes:
        db.session.delete(_pass)

    db.session.delete(user)
    db.session.commit()
