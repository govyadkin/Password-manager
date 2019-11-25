import random
import datetime
from math import log2
from app.models import User

Active_time = 30


def check_token(u: User) -> bool:
    return (u is None or
            (datetime.datetime.utcnow() - u.timestamp) > datetime.timedelta(minutes=Active_time))


def hard_pass(password):
    n = 0
    flag = [True, True, True, True, True, True]
    for i in password:
        if flag[0] and '9' >= i >= '0':
            n += 10
        elif flag[1] and 'A' >= i >= 'Z':
            n += 26
        elif flag[2] and 'a' >= i >= 'z':
            n += 26
        elif flag[3] and chr(96) >= i >= '[' and '~' >= i >= '{':
            n += 10
        elif flag[4] and '@' >= i >= ':':
            n += 7
        elif flag[5] and '/' >= i >= ' ':
            n += 16
    return {"hard_pass": len(password) * log2(n)}


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
        if i == 39 or i == 92:
            i += 1
        password += chr(i)
    return ''.join(random.sample(password, len(password)))
