import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    # SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEqQIBAAKCAQEAuDlL4cO+HDt72+xlPeSxsETsrDBjWQLGNt4sHkQ1SkbGkPW7
liG7bSrtShNjTSfbWQr1yhwzXaHszAHqqMnQp2YWQqNdrLb0isMBMWT8zp7w/vd1
AWjPHt0u7HKqA05/m2EVuqi16h1zc0cT4qdlET3eF1g0drfUcuXEqpfBzekWQOMa
P0hTir+h669Uzdl/BfYhgiGg7UC0pcvzftajqQoLN6NfxkKV9Nr2hq2jy0kFQwrV
ZVBQ3nqM1lKtqJnrxm2P2Q2/w4hjKg3VMwRoSq7/BLJMoj6tq6rHsQNZMRZy+K1C
X4ynBwTo0uWOpxlUyB5XZD9m8RFM5mLRZfUSRwIDAQABAoIBAAvyW0NmyDtYeC3I
5L/gxs0hix+Xe7nX/jasrbvAvJv2fwYDiYiw41CvCfhVzYjBXu4lUc8riQE3cP3B
2g/cFpXkfukPYxHCQ5WEE926KNLVZ9eBAKt4uoXL3jEjNndEbe4Lm7chHbry8fu1
zkpShLFbi72D0NMqFKSJb4IH+e7Wjz+ZpT/balRXlfy7AuGn4N+tA4P2Co6A8BEE
2uG9kPKXsOamkFHm/J7SY7Q8rcQXSqS63E9xzWU6xy6gJ74i1E4Wqivho7UiKNht
GJxgMygGK6dcpEaFCp5nS7ldak6E3p/jeEdDq8fTeUGmWccOKDkqtpRu7/fLSHlU
nDMa0KECgYkA3YJglmKC3qBRRkEjjas4sDtMcM3cu+zVTA63ny/sX5tatuhz/XFg
31DObRoH5NtyHe1kCTXcKdMOS7eml3Tj2HI1UX6aJ44RHSDrgIQO3V84cEvZGiAM
hv41nfbXfddszNrBAyhRn4+l4kuGqkeF7S15YitxMLNJc3BwKcqodk448ZrrmM6n
fwJ5ANTorQ6MY62f/rMOwIQqlOeTZnXgNRxVsTrGG2eNlRD419S5PnBPeaRNOMU0
sFXF/TpP9xMPY/p61PjHXrF4l74R35bLN83bz6hfiStGsOnGYpzRgwUX9NgMxUyk
DTd0A9chERjW5wrkN/NuFhpd8EQV95taEpm5OQKBiQDRHXptvoZqAdN4jZow7knQ
JcseW1pdl1IuQV6cS7PM9m8Hah/GTjjz2ednHEIDjiAHnMrp3wz/9x3x4WjGZzWK
axdm3ixN11LUuvVZGFKoLnKroQ9OGJ96+ZZIkHYTeUJfiszYXEHibsxd/IsfSfJn
XJzRTs3G+hsHfkiFS6sKNQKRJH3yfnWlAngXOmNXCP3+/UueYWejg7nHIg+1oIZq
1vaFAQQQYiP3PA7gCG3FdwZAZKRi74KlePpNmFfOXol71FbT5XxxRETZ2b1ZCEbI
UMjxB6tBa271sk0j6r+umJR/1bTYzbUbba7Vk6f328pNJ+TqzAHhUopaA0OGUWdi
GhECgYh9dW5sUmqPlCgjCVPpjnDaz9QmTVeszCYhJDoi/qJ1k5EjHl+vvbs56Fgy
nVuoNYjVwQrCZNVkc6U8uYjf92lRR6N4MkBwkX25K5Xba2gknza5lNGAqRtN2ysO
d90WQudrfjA+d76WtpxqSQG04OBeWpHTTMIMvhWhhFMRB9+qTObTNJHX/zkf
-----END RSA PRIVATE KEY-----"""
