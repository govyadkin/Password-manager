FROM python:3.6

WORKDIR PasswordManager

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip

RUN pip install -r requirements.txt

COPY app app
COPY migrations migrations
COPY app.py config.py cripto.py halper_func.py ./

ENV FLASK_APP app.py

EXPOSE 5000

ENTRYPOINT [ "python" ]

CMD [ "app.py" ]