from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
from flask import render_template

import pprint
import os

app = Flask(__name__)

app.debug = True #Change this to False for production

app.secret_key = os.environ['SECRET_KEY']
oauth = OAuth(app)

#delete this when running heroku
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
#https://spewds-oauth.herokuapp.com/ (homepage URL)use this when done with running locally
#https://spewds-oauth.herokuapp.com/login/authorized (authorized callback)

#set up Github as the OAuth Provider
github = oauth.remote_app(
    'github',
    consumer_key=os.environ['GITHUB_CLIENT_ID'], 
    consumer_secret=os.environ['GITHUB_CLIENT_SECRET'],
    request_token_params={'scope': 'user:email'}, #request read-only access to the user's email.  For a list of possible scopes, see developer.github.com/apps/building-oauth-apps/scopes-for-oauth-apps
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',  
    authorize_url='https://github.com/login/oauth/authorize' #URL for github's OAuth login
)


@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

@app.route('/')
def home():
    if 'user_data' in session:
        user_data_pprint = pprint.pformat(session['user_data']['location'])#format the user data nicely
    else:
        user_data_pprint = ''
    return render_template('home.html',dump_user_data=user_data_pprint)

@app.route('/login')
def login():
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='http'))#set this back https

@app.route('/logout')
def logout():
    session.clear()
    return render_template('home.html', message='You were logged out')

@app.route('/login/authorized')#the route should match the callback URL registered with the OAuth provider
def authorized():
    resp = github.authorized_response()
    if resp is None:
        session.clear()
        message = 'Access denied: reason=' + request.args['error'] + ' error=' + request.args['error_description'] + ' full=' + pprint.pformat(request.args)      
    else:
        try:
            #save user data and set log in message
            session['github_token'] = (resp['access_token'], '')
            session['user_data'] = github.get('user').data
            message = "You were successfully logged in as " + session['user_data']['login'] + '.'
        except Exception as inst:
            #clear the session and give error message
            session.clear()
            print(inst)
            message = "Unable to log in. Please try again."
    return render_template('home.html', message=message)
    
@github.tokengetter
def get_github_oauth_token():
    return session['github_token']


if __name__ == '__main__':
    app.run()
