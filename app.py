import json
import sqlite3
import random
from sql import create_tables, initialisation, print_all
from flask import Flask, request, send_from_directory
from math import log2

app = Flask(__name__)


def gen_password(n):
    password = ""
    password = (chr(random.randint(48, 57)) +
                chr(random.randint(32, 47)) +
                chr(random.randint(58, 64)) +
                chr(random.randint(65, 90)) +
                chr(random.randint(91, 96)) +
                chr(random.randint(97, 122)) +
                chr(random.randint(123, 126)))
    while n > len(password):
        password += chr(random.randint(32, 126))
    return ''.join(random.sample(password, len(password)))


@app.route('/', methods=['GET'])
def hello_world():
    return 'Hello Password Manager!'


@app.route('/admin_use')
def admin_use():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    data = print_all(cursor)
    s = ""
    for elem in data:
        s += json.dumps(elem) + ", "

    conn.close()
    return s


@app.route('/authentication')
def authentication():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""
               SELECT user_id
               FROM Users
               WHERE login = ? AND password = ?""",
                   [(data['login']), (data['password'])])
    results = cursor.fetchall()
    # if results.count() == 0:
    #   print("Error authentication")
    #  return "Error"
    token = gen_password(20)
    cursor.execute("UPDATE Users SET token = ? WHERE user_id = ?",
                   [token, (results[0][0])])
    conn.commit()
    conn.close()
    return token


@app.route('/authentication/gen_pass')
def gen_pass():
    n = request.data.decode('UTF-8')
    if n < 8:
        print("Error gen_pass")
    return gen_password(n)


@app.route('/authentication/hard_pass')
def hard_pass():
    password = request.data.decode('UTF-8')
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
    return str(len(password) * log2(n))


@app.route('/getter')
def getter():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""
           SELECT login, password
           FROM Password
           WHERE name_place = ? AND user_id = (SELECT user_id FROM Users WHERE token = ?)""",
                   [(data['name_place']), (data['token'])])
    results = cursor.fetchall()
    conn.close()
    s = ""
    for elem in results:
        s += json.dumps({"login": elem[0], "password": elem[1]})
    return s


@app.route('/insert', methods=['POST'])
def insert():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""
    INSERT INTO Password(name_place, login, password, user_id, tag)
    VALUES (?,?,?,(SELECT user_id FROM Users WHERE token=?),?)
    """, [(data["name_place"]), (data['login']), (data['password']), (data['token']), (data['tag'])])
    conn.commit()
    conn.close()
    return "Success"


@app.route('/update', methods=['POST'])
def update():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""UPDATE Password
    SET login = ?, password = ?, tag = ?
    WHERE name_place = ? AND user_id = (SELECT user_id FROM Users WHERE token = ?) AND 
    login = ?""",
                   [(data['new_login']), (data['new_password']), (data['new_tag']),
                    (data['name_place']), (data['token']), (data['login'])])

    conn.commit()
    conn.close()
    return "Success"


@app.route('/update/user', methods=['POST'])
def update_user():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""UPDATE Users
    SET login = ?, password = ?
    WHERE  token = ?""",
                   [(data['new_login']), (data['new_password']),(data['token'])])

    conn.commit()
    conn.close()
    return "Success"


@app.route('/delete', methods=['POST'])
def delete():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""DELETE FROM Password
    WHERE name = ? AND
    user_id = (SELECT user_id FROM Users WHERE token = ?)""",
                   [(data['name']), (data['token'])])
    conn.commit()
    conn.close()
    return "Success"


@app.route('/delete/user', methods=['POST'])
def delete_user():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""DELETE FROM Password
    WHERE user_id = (SELECT user_id FROM Users WHERE token = ?)""",
                   [(data['token'])])
    conn.commit()
    cursor.execute("DELETE FROM Users WHERE token = ?",
                   [(data['token'])])
    conn.close()


@app.route('/upload')
def upload():
    conn = sqlite3.connect("mydatabase.db")
    cursor = conn.cursor()

    json_string = request.data.decode('UTF-8')
    data = json.loads(json_string)

    cursor.execute("""
            SELECT Password.name_place, 
                   Password.login,
                   Password.password,
                   Password.tag
            FROM Password 
            WHERE user_id = (SELECT user_id FROM Users WHERE token = ?)""", [(data['token'])])
    results = cursor.fetchall()
    result = ""
    for elem in results:
        result += json.dumps({"name_place": elem[0], "login": elem[1], "password": elem[2], "tag": elem[3]}) + ", "

    conn.close()
    return result


if __name__ == '__main__':
    app.run()
