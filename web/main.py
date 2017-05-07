import logging

import requests
from flask import Flask, url_for, redirect, render_template, flash, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Length, EqualTo, Email
from pymongo import MongoClient

app = Flask("web", template_folder="templates")
# Load configuration values for the web component (secret key used for CSRF, port and hostname).
app.config.from_pyfile('config.cfg')
logging.basicConfig(level=logging.DEBUG)
# Enable the Bootstrap plugin to make the UI more attractive.
Bootstrap(app)

mongo = MongoClient("db", 27017)
users_collection = mongo.database.users


def get_api_url(endpoint):
    return "http://{}:{}{}".format(app.config['API_HOSTNAME'], app.config['API_PORT'], endpoint)


class MessageForm(FlaskForm):
    name = StringField("Your name")
    message = StringField("Your message")
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email_address = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    email_address = StringField('Email', validators=[InputRequired(), Email(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=25)])
    password_repeat = PasswordField('Repeat Password', validators=[InputRequired(),
                                                                   EqualTo('password', message='Passwords must match.')])
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=60)])
    submit = SubmitField('Register')


@app.route('/', methods=['GET', 'POST'])
def show_index():
    if "name" in session:
        return redirect('/home')
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        r = requests.post(get_api_url('/login'),
                          json={"email_address": form.email_address.data, "password": form.password.data})
        data = r.json()
        app.logger.info("Received Login Data '{}' from '{}'".format(form.login.data, form.name.data))
        if data['error'] is None:
            user = users_collection.find_one({'name': form.name.data})
            session['id'] = user['_id']
            session['name'] = user['name']
            flash('Successfully logged in!', 'success')
            return redirect(url_for('show_home'))
    return render_template('index.html', login_form=form)

@app.route('/logout')
def logout():
    flash(session['name'] + " has logged out!", "message")
    session.clear()
    return redirect(url_for(show_index))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        r = requests.post(get_api_url('/register'),
                          json={"email_address": form.email_address.data,
                                "password": form.password.data,
                                "name": form.name.data})
        data = r.json()
        if data['error'] is None:
            user = users_collection.find_one({'name': form.name.data})
            session['id'] = user['_id']
            session['name'] = user['name']
            flash('Successfully Registered!', 'success')
            return redirect(url_for('show_index'))
    return render_template('index.html', register_form=form)


@app.route('/home', methods=['GET', 'POST'])
def show_home():
    if "name" not in session:
        return redirect(url_for('show_index'))
    # List containing the previous messages (should be retrieved from API later).
    r = requests.get("http://api:5000/messages")
    data = r.json()
    messages = data['data']
    form = MessageForm()
    if form.validate_on_submit():
        # Log the received message (should be processed by the API later).
        app.logger.info("Received message '{}' from '{}'".format(form.message.data, form.name.data))
        r = requests.post('http://api:5000/send', json={
            "author": form.name.data,
            "message": form.message.data
        })
        data = r.json()
        app.logger.info("Received following response from the API: {}".format(data))
        # If the message is successfully received, redirect the user to the GET version of the page
        # to prevent them from sending the message again when refreshing.
        return redirect(url_for('show_home'))
    return render_template('index.html', form=form, messages=messages)


def main():
    app.run(host=app.config['HOSTNAME'], port=int(app.config['PORT']))


if __name__ == "__main__":
    main()
