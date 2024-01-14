from flask import Flask, request, redirect, jsonify, make_response
import requests
import base64
import os

app = Flask(__name__)

# Replace these with your actual client ID and secret from EVE SSO
client_id = os.environ.get('CLIENT_ID')
client_secret = os.environ.get('CLIENT_SECRET')
callback_url = os.environ.get('CALLBACK_URL')

@app.route('/')
def index():
    # Redirect user to EVE SSO for authorization
    auth_url = (
        'https://login.eveonline.com/oauth/authorize'
        '?response_type=code'
        f'&redirect_uri={callback_url}'
        f'&client_id={client_id}'
        '&scope=esi-characters.read_blueprints.v1'
        '&state=unique-state-string'  # Generate and verify this value for each request
    )
    return redirect(auth_url, code=302)

@app.route('/callback/')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        return jsonify({'error': 'Missing authorization code'}), 400

    # Exchange the authorization code for an access token
    auth_string = f'{client_id}:{client_secret}'
    auth_bytes = auth_string.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')

    headers = {
        'Authorization': f'Basic {auth_b64}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': callback_url
    }

    token_response = requests.post('https://login.eveonline.com/v2/oauth/token', headers=headers, data=data)
    token_data = token_response.json()

    if 'error' in token_data:
        return jsonify(token_data), 400

    # Set the access token in a secure cookie and redirect to your main app
    response = make_response(redirect('https://mineskitycoon.neocities.org/index.html', code=302))
    response.set_cookie('accessToken', token_data['access_token'], secure=True, httponly=True, samesite='Strict')
    return response

if __name__ == '__main__':
    app.run()