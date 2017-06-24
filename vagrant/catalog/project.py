from flask import Flask, render_template, request, redirect, make_response, url_for
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import OAuth2Credentials
import httplib2
import json
import requests

from dbhelper import *

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']


@app.route('/')
@app.route('/catalog/')
def index():
    categories = get_all_categories()
    items = get_all_items()[0:11]
    if not login_session.get('state'):
        state = ''.join(random.choice(string.ascii_lowercase +
                                      string.ascii_uppercase + string.digits) for x in range(32))
        login_session['state'] = state
    return render_template('catalog.html', username=login_session.get('username'), categories=categories, items=items, STATE=login_session.get('state'))


@app.route('/catalog/<category>/items/')
def items(category):

    items = get_items_by_category(category)
    allCat = get_all_categories()

    return render_template('catalog.html', categories=allCat, username=login_session.get('username'), items=items, tittle=category, STATE=login_session.get('state'))


@app.route('/catalog/<category>/<item>/')
def item(category, item):
    all_categories = get_all_categories()
    current_item = get_item_by_name_and_category(category, item)
    return render_template('item.html', categories=all_categories, current_item=current_item, username=login_session.get('username'), title=item, STATE=login_session.get('state'))


@app.route('/catalog/item/add', methods=['GET', 'POST'])
def add_item():
    if not login_session.get('username'):
        return redirect(url_for('index'))
    categories = get_all_categories()
    if request.method == 'POST':
        name, description, cat_id, valid_category = extract_form_data()
        if valid_category and name and cat_id:
            item = Item(name=name, cat_id=cat_id, description=description)
            add_item_todb(item)
        return redirect(url_for('index'))
    return render_template('add.html', categories=categories, STATE=login_session.get('state'), username=login_session.get('username'))


@app.route('/catalog/<category>/<item>/edit/')
def edit_item(category, item):
    if not login_session.get('username'):
        return redirect(url_for('index'))
    categories = get_all_categories()
    current_item = get_item_by_name_and_category(category, item)
    if not current_item:
        return redirect(url_for('index'))
    return render_template('edit.html', item=current_item, categories=categories, STATE=login_session.get('state'), username=login_session.get('username'))


@app.route('/catalog/item/edit/', methods=['POST'])
def save_item():
    if not login_session.get('username') or request.method == 'GET':
        return redirect(url_for('index'))
    id = request.form.get('id')
    item = get_item_by_id(id)
    if item:
        name, description, cat_id, valid_category = extract_form_data()
        if valid_category and name and cat_id:
            item.name = name
            item.description = description
            item.cat_id = cat_id
            add_item_todb(item)
            return redirect('/catalog/%s/%s/' % (item.cat.name, item.name))
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))


def extract_form_data():
    valid_category = False
    name = request.form.get('name')
    description = request.form.get('description')
    cat_id = request.form.get('category')
    cat = get_category_by_id(cat_id)
    if cat:
        valid_category = True

    return name, description, cat_id, valid_category


@app.route('/catalog/<category>/<item>/delete/')
def delete_item(category, item):
    if not login_session.get('username'):
        return redirect(url_for('index'))
    categories = get_all_categories()
    current_item = get_item_by_name_and_category(category, item)
    message = 'Could not delete item'
    if current_item:
        delete_item_fromdb(current_item)
        message = 'Item deleted'
    return render_template('delete.html', categories=categories, STATE=login_session.get('state'), message=message, username=login_session.get('username'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session.get('state'):
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
    login_session['access_token'] = access_token

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
    output += '<h1>Welcome %s </h1>' % login_session.get('username')
    output += '<img src="%s" width=75px />' % login_session['picture']

    return output


@app.route('/logout/')
def logout():
    access_token = login_session.get('access_token')
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session.get('username'))
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('index'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'secret key'
    app.run(host='0.0.0.0')
