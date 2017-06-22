from flask import Flask, render_template, request, redirect, make_response, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import OAuth2Credentials
import httplib2
import json
from flask import make_response
import requests

engine = create_engine('postgresql://vagrant:password@localhost:5432/catalogs')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']


@app.route('/')
@app.route('/catalog/')
def index():
    cat = session.query(Category)
    output = ''
    for c in cat.all():
        output += c.name
        output += '<br>'
    return output


@app.route('/catalog/<category>/items/')
def items(category):
    category = category.title()
    output = ''
    for c, i in session.query(Category, Item).filter(Category.name == category).filter(Item.cat_id == Category.id):
        output += i.name + '<br>'
    return output


@app.route('/catalog/<category>/<item>/')
def item(category, item):
    category, item = [category.title(), item.title()]
    output = ''
    for c, i in session.query(Category, Item).filter(Category.name == category).filter(Item.name == item):
        output += i.description + '<br>'
    return output


@app.route('/catalog/<category>/item/add')
def add_item(category):
    if 'username' not in login_session:
        return redirect(url_for('login'))
    return 'Hello %s. You are allowed to add items' % login_session['username']


@app.route('/catalog/<category>/<item>/edit')
def edit_item():
    return 'Edit an item'


@app.route('/catalog/<category>/<item>/delete')
def delete_item():
    return 'Delete an item'


@app.route('/login/')
def login():
    state = ''.join(random.choice(string.ascii_lowercase +
                                  string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state

    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code).to_json()
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = OAuth2Credentials.from_json(credentials).access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = OAuth2Credentials.from_json(credentials).id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id
    login_session['access_token']= access_token

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': OAuth2Credentials.from_json(
        credentials).access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome %s </h1>' % login_session['username']
    output += '<img src="%s" width=75px />' % login_session['picture']

    return output


@app.route('/logout/')
def logout():
    access_token = login_session['access_token']
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ' )
    print(login_session['username'])
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print (result)
    if result['status'] == '200':
        del login_session['access_token'] 
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('index'))
    else:
	
    	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'secret key'
    app.run(host='0.0.0.0')
