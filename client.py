import json

import requests
import rsa

(pub_client, priv_client) = rsa.newkeys(2048)

# url = 'http://194.87.92.173:5000'

url = 'http://127.0.0.1:5000'

login = 'admin_user_m'
password = 'Qwerty13535135'

print('signup')

data = requests.post(url=url + '/user/signup', data=json.dumps({'login': login,
                                                                'password': password,
                                                                'open_key_client': pub_client.save_pkcs1(
                                                                    'PEM').decode()}).encode()).content.decode()
print(data)
data = json.loads(data)

pub_server = rsa.PublicKey.load_pkcs1(data['open_key_server'].encode())

print('sign_in')

message = rsa.encrypt(json.dumps({'login': login, 'password': password}).encode(), pub_server)

data = requests.put(url=url + '/user/sign_in', data=message)
cookies = data.cookies
data = data.content.decode()
print(data)

print('/password/insert')

message = rsa.encrypt(
    json.dumps({'key': password, 'name_place': 'bmstu', 'login': 'misha', 'password': 'Qwerty'}).encode(), pub_server)
data = requests.post(url=url + '/password/insert', data=message, cookies=cookies).content.decode()

print(data)

print('/password/get/all')

message = rsa.encrypt(json.dumps({'key': password}).encode(), pub_server)
data = requests.get(url=url + '/password/get/all', data=message, cookies=cookies).content
data = rsa.decrypt(data, priv_client)

print(data)

print('delete/user')
data = requests.delete(url=url + '/delete/user', cookies=cookies).content.decode()

print(data)
# message1 = rsa.decrypt(data, pri)
# print(message1)
