from pickle import FALSE

from flask import Blueprint, jsonify, request

from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt,
    current_user,
    get_jwt_identity
)

from models.user import User
from models.token_blocklist import TokenBlocklist

auth_bp = Blueprint('auth', __name__)


@auth_bp.post("/register")
def register_user():
    data = request.get_json()
    user = User.get_user_by_username(data['username'])

    if user is not None:
        return jsonify({"error": "User already exists"}), 409

    new_user = User(data['username'], data['email'], data['password'], data['cpf_cnpj'])
    new_user.save_to_db()

    return jsonify({"message": "User created"}), 201

@auth_bp.post("/login")
def login_user():
    data = request.get_json()
    user = User.get_user_by_username(data['username'])

    if user and (user.check_password(data['password'])):
        access_token = create_access_token(identity=data['username'])
        refresh_token = create_refresh_token(identity=data['username'])

        return (
            jsonify(
                {
                    "message": "Login successful",
                    "tokens": {"access_token": access_token, "refresh_token": refresh_token}
                }
            ), 200
        )

    return jsonify({"message": "Invalid credentials"}), 401

@auth_bp.get("/logout")
@jwt_required(verify_type=False)
def logout_user():
    jwt = get_jwt()
    jti = jwt['jti']
    token_type = jwt['type']

    token_b = TokenBlocklist(jti=jti)
    token_b.save_to_db()

    return jsonify({"message": f" {token_type} token revoked successfully"}), 200

@auth_bp.get("/refresh")
@jwt_required(refresh=True)
def refresh_token():
    identity = get_jwt_identity()
    new_access_token = create_access_token(identity=identity)

    return jsonify({"access_token": new_access_token}), 200


@auth_bp.get("/whoami")
@jwt_required()
def whoami():
    return jsonify(
        {
            "message": "message",
            "user_details": {
                "username": current_user.username,
                "email": current_user.email,
                "cpf_cnpj": current_user.cpf_cnpj
            }
        }
    )
