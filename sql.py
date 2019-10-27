import json
import sqlite3

conn = sqlite3.connect("mydatabase.db")
cursor = conn.cursor()


def create_tables():
    cursor.execute("""CREATE TABLE Password
                      (name_place text, login text, password text, user_id integer, tag text)
                   """)
    cursor.execute("""CREATE TABLE Users
                          (user_id integer PRIMARY KEY AUTOINCREMENT, login text, password text, token text)
                       """)
    conn.commit()


def initialisation():
    cursor.execute("INSERT INTO Users(login, password) VALUES ('Misha', 'IU8-31')")
    cursor.execute("""INSERT INTO Password ( name_place, login,password, user_id, tag)
                  VALUES ('Andy Hunter', '7/24/2012',
                  'Xplore Records', 1, 'work')"""
               )
    conn.commit()
    albums = [('Andy Hunter', '7/9/2002', 'Sparrow Records', 1, 'work'),
          ('Red', '2/1/2011', 'Essential Records', 1, 'work'),
          ('Thousand Foot Krutch', '4/17/2012', 'TFKmusic', 1, 'work'),
          ('Trip Lee', '4/10/2012', 'Reach Records', 1, 'work')]
    cursor.executemany("INSERT INTO Password( name_place, login,password, user_id, tag) VALUES (?,?,?,?,?)", albums)
    conn.commit()


def print_all(cursor):
    cursor.execute("""
    SELECT Users.login,
           Password.name_place, 
           Password.login,
           Password.password,
           Password.tag
    FROM Password 
    INNER JOIN Users
    ON Password.user_id = Users.user_id;""")
    results = cursor.fetchall()
    data = []
    for elem in results:
        data.append({"login_user": elem[0], "name_place": elem[1], "login": elem[2], "password": elem[3], "tag": elem[4]})
    return data
