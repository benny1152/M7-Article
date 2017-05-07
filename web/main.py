import logging

import requests
from flask import Flask, url_for, redirect, render_template, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Length, EqualTo, Email

app = Flask("web", template_folder="templates")
# Load configuration values for the web component (secret key used for CSRF, port and hostname).
app.config.from_pyfile('config.cfg')
logging.basicConfig(level=logging.DEBUG)
# Enable the Bootstrap plugin to make the UI more attractive.
Bootstrap(app)


# Simplifies making requests to a particular endpoint
def get_api_url(endpoint):
    return "http://{}:{}{}".format(app.config['API_HOSTNAME'], app.config['API_PORT'], endpoint)


# WTF Forms for logging in and registering
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


# Renders the home template for the login and register endpoints to load their forms onto
@app.route('/', methods=['GET', 'POST'])
def show_index():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Makes a request to the api/main.py /login endpoint with the form parameters
        r = requests.post(get_api_url('/login'),
                          json={"email_address": form.email_address.data, "password": form.password.data})
        data = r.json()
        app.logger.info("Received Login Data '{}' from '{}'".format(form.login.data, form.name.data))
        # If there was no error in the login POST request
        if data['error'] is None:
            flash('Successfully logged in!', 'success')
            return redirect(url_for('show_index'))
    return render_template('home.html', login_form=form)


# Similar endpoint formatting to the above /login endpoint
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
            flash('Successfully Registered!', 'success')
            return redirect(url_for('show_index'))
    return render_template('home.html', register_form=form)


def main():
    app.run(host=app.config['HOSTNAME'], port=int(app.config['PORT']))


if __name__ == "__main__":
    main()
