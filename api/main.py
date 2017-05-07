import logging

from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import bcrypt

app = Flask("api")
bcrypt = Bcrypt(app)
# Load configuration values for the API component (port and hostname).
app.config.from_pyfile('config.cfg')
logging.basicConfig(level=logging.DEBUG)

# Configure the connection to the database
mongo = MongoClient("db", 27017)


# The collection containing the information about the users
users_collection = mongo.database.users


@app.route('/login', methods=['POST'])
def login():
    login_data = request.get_json()
    email_address, password = login_data['email_address'], login_data['password']
    data = dict()
    logging.debug("API login, received data: {} {}".format(email_address, password))
    login_user = users_collection.find_one({'email_address': email_address})
    if login_user is not None:
        logging.debug('password: {}'.format(password.encode('utf-8')))
        logging.debug('hash:     {}'.format(login_user.password_hash))
        if bcrypt.check_password_hash(password.encode('utf-8'), login_user.password_hash.encode('utf-8')):
            data['result'] = {'success': True, 'email_address': email_address}
            data['error'] = None
    else:
        data['result'] = {'success': False}
        data['error'] = "Example Error Message"
    return jsonify(data)


@app.route('/register', methods=['POST'])
def register():
    registration = request.get_json()
    data = dict()
    logging.debug("Data: {}".format(registration))
    hashed_password = bcrypt.generate_password_hash(registration['password'].encode('utf-8'))
    new_user = users_collection.insert_one({'name': registration['name'], 'password_hash': hashed_password,
                                           'email_address': registration['email_address']})
    logging.debug("New user: {}".format(new_user))
    if new_user is not None:
        data['result'] = {'success': True, 'user_id': str(new_user)}
        data['error'] = None
    else:
        data['result'] = {'success': False}
        data['error'] = "Example Error Message"
    return jsonify(data)


def main():
    app.run(host=app.config['HOSTNAME'], port=int(app.config['PORT']))


if __name__ == "__main__":
    main()