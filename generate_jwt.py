import json
import os
import datetime
import jwt
from google.oauth2 import service_account
import argparse
from dotenv import load_dotenv
import subprocess
import sys

def check_install_dependencies():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        sys.exit(1)

def generate_jwt(service_account_file, audience):
    if not os.path.exists(service_account_file):
        raise FileNotFoundError(f"Service account file '{service_account_file}' does not exist.")

    with open(service_account_file) as f:
        service_account_info = json.load(f)

    now = datetime.datetime.now(datetime.timezone.utc)

    payload = {
        'iat': now,
        'exp': now + datetime.timedelta(minutes=60),
        'aud': audience,
        'iss': service_account_info['client_email']
    }

    jwt_token = jwt.encode(
        payload,
        service_account_info['private_key'],
        algorithm='RS256',
        headers={'kid': service_account_info['private_key_id']}
    )

    return jwt_token

def save_token_to_file(token):
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%d_%m_%Y")
    filename = f'token_{date_str}.txt'
    with open(filename, 'w') as f:
        f.write(f"Bearer {token}\n")
    print(f"Token saved to '{filename}'.")

def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Generate JWT for Google Cloud IAP")
    parser.add_argument("--service-file", "-sF", default='./service.json', help="Path to the service account file")
    parser.add_argument("--install-dependencies", "-I", action="store_true", help="Install required dependencies")
    args = parser.parse_args()

    if args.install_dependencies:
        check_install_dependencies()
        print("Dependencies installed successfully.")
        return

    audience = os.getenv('AUDIENCE')
    if not audience:
        raise EnvironmentError("Audience URL is not set in the .env file")

    jwt_token = generate_jwt(args.service_file, audience)

    print("Your JWT:", jwt_token)
    save_token_to_file(jwt_token)

if __name__ == "__main__":
    main()
