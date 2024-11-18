"""Python Flask API Auth0 integration example
"""

import json
from functools import wraps
from os import environ as env
from typing import Dict

from dotenv import find_dotenv, load_dotenv
from flask import Flask, Response, g, jsonify, request, url_for
from flask_cors import cross_origin
from jose import jwt
from six.moves.urllib.request import urlopen

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
API_IDENTIFIER = env.get("API_IDENTIFIER")
ALGORITHMS = ["RS256"]
APP = Flask(__name__)

DATA = [
    {"id": 1, "name": "Item 1"},
    {"id": 2, "name": "Item 2"},
    {"id": 3, "name": "Item 3"},
    {"id": 4, "name": "Item 4"},
    {"id": 5, "name": "Item 5"},
    {"id": 6, "name": "Item 6"},
    {"id": 7, "name": "Item 7"},
    {"id": 8, "name": "Item 8"},
]


# Format error response and append status code.
class AuthError(Exception):
    """
    An AuthError is raised whenever the authentication failed.
    """

    def __init__(self, error: Dict[str, str], status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


@APP.errorhandler(AuthError)
def handle_auth_error(ex: AuthError) -> Response:
    """
    serializes the given AuthError as json and sets the response status code accordingly.
    :param ex: an auth error
    :return: json serialized ex response
    """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def get_token_auth_header() -> str:
    """Obtains the access token from the Authorization Header"""
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError(
            {
                "code": "authorization_header_missing",
                "description": "Authorization header is expected",
            },
            401,
        )

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Authorization header must start with" " Bearer",
            },
            401,
        )
    if len(parts) == 1:
        raise AuthError(
            {"code": "invalid_header", "description": "Token not found"}, 401
        )
    if len(parts) > 2:
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Authorization header must be" " Bearer token",
            },
            401,
        )

    token = parts[1]
    return token


def requires_scope(required_scope: str) -> bool:
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False


def requires_auth(func):
    """Determines if the access token is valid"""

    @wraps(func)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError as jwt_error:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Invalid header. "
                    "Use an RS256 signed JWT Access Token",
                },
                401,
            ) from jwt_error
        if unverified_header["alg"] == "HS256":
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Invalid header. "
                    "Use an RS256 signed JWT Access Token",
                },
                401,
            )
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer="https://" + AUTH0_DOMAIN + "/",
                )
            except jwt.ExpiredSignatureError as expired_sign_error:
                raise AuthError(
                    {"code": "token_expired", "description": "token is expired"}, 401
                ) from expired_sign_error
            except jwt.JWTClaimsError as jwt_claims_error:
                raise AuthError(
                    {
                        "code": "invalid_claims",
                        "description": "incorrect claims,"
                        " please check the audience and issuer",
                    },
                    401,
                ) from jwt_claims_error
            except Exception as exc:
                raise AuthError(
                    {
                        "code": "invalid_header",
                        "description": "Unable to parse authentication" " token.",
                    },
                    401,
                ) from exc
            # ctx = request._get_current_object()
            # print(ctx)
            g.user = payload
            return func(*args, **kwargs)
        raise AuthError(
            {"code": "invalid_header", "description": "Unable to find appropriate key"},
            401,
        )

    return decorated


# Controllers API
@APP.route("/api/public")
@cross_origin(headers=["Content-Type", "Authorization"])
def public():
    """No access token required to access this route"""
    response = (
        "Hello from a public endpoint! You don't need to be authenticated to see this."
    )
    return jsonify(message=response)


@APP.route("/api/locations")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://localhost:3000"])
@requires_auth
def get_items():
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=5, type=int)

    # Validate pagination parameters
    if page < 1 or per_page < 1:
        return jsonify({"error": "Page and per_page must be positive integers"}), 400

    # Calculate start and end indices
    start = (page - 1) * per_page
    end = start + per_page

    # Slice the data for pagination
    paginated_data = DATA[start:end]

    total_items = len(DATA)
    total_pages = (total_items + per_page - 1) // per_page  # Round up

    # Generate next link if there's a next page
    next_link = None
    if page < total_pages:
        next_link = url_for(
            "get_items", page=page + 1, per_page=per_page, _external=True
        )

    # Return the paginated response with metadata
    response = jsonify(
        {
            "data": paginated_data,
            "meta": {
                "total_items": total_items,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "next": next_link,
            },
        }
    )
    return response


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=env.get("PORT", 3000), debug=True)
