from flask import Flask, request, redirect, jsonify, make_response
import requests
import base64
import os

app = Flask(__name__)

# Replace these with your actual client ID and secret from EVE SSO
client_id = os.environ.get('eve_client_id')
client_secret = os.environ.get('eve_client_secret')
callback_url = os.environ.get('eve_callback_url')

auth_string = f'{client_id}:{client_secret}'
print(f'Auth String: {auth_string}')  # Log the auth string for debugging

auth_bytes = auth_string.encode('utf-8')
auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
print(f'Auth Base64: {auth_b64}')  # Log the base64-encoded auth string for debugging

@app.route('/')
def index():
    # Redirect user to EVE SSO for authorization
    auth_url = (
        'https://login.eveonline.com/oauth/authorize'
        '?response_type=code'
        f'&redirect_uri={callback_url}'
        f'&client_id={client_id}'
        '&scope=esi-wallet.read_character_wallet.v1 esi-corporations.read_corporation_membership.v1 esi-planets.manage_planets.v1 esi-markets.structure_markets.v1 esi-characters.read_corporation_roles.v1 esi-killmails.read_corporation_killmails.v1 esi-corporations.read_titles.v1'
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
    client_id = os.environ.get('eve_client_id')  # Use the actual name of your environment variable
    client_secret = os.environ.get('eve_client_secret')  # Use the actual name of your environment variable
    callback_url = os.environ.get('eve_callback_url')  # Use the actual name of your environment variable

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
        'redirect_uri': callback_url,
    }

    token_response = requests.post(
        'https://login.eveonline.com/v2/oauth/token',
        headers=headers,
        data=data
    )

    # Log the response for debugging
    print(f'Status Code: {token_response.status_code}')
    print(f'Response Headers: {token_response.headers}')
    print(f'Response Content: {token_response.text}')

    # Check the status code before decoding JSON
    if token_response.status_code != 200:
        return jsonify({'error': 'Failed to retrieve token', 'details': token_response.text}), token_response.status_code

    try:
        token_data = token_response.json()
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON response', 'details': token_response.text}), 500

    if 'error' in token_data:
        return jsonify(token_data), 400

    # Set the access token in a secure cookie and redirect to your main app
    response = make_response(redirect('https://mineskitycoon.neocities.org', code=302))
    response.set_cookie('accessToken', token_data['access_token'], secure=True, httponly=False, samesite='Lax', domain='mineskitycoon.neocities.org')
    return response


if __name__ == '__main__':
    app.run()