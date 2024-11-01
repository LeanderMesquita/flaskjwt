from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt

from database.schemas import UserSchema
from models.user import User

user_bp = Blueprint('user', __name__)

@user_bp.get("/all")
@jwt_required()
def get_all_users():
    claims = get_jwt()

    if claims.get("is_staff"):
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 10, type=int)
        users = User.query.paginate(page=page, per_page=per_page)
        result = UserSchema(many=True).dump(users)

        return (
            jsonify(
                {
                    'users': result
                }
            )
        )

    return jsonify({"message": "You are not logged in!"}), 403