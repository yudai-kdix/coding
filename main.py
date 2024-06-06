import base64
from flask import Flask, request, jsonify


app = Flask(__name__)

# ユーザー情報を管理するための辞書
users = {}

@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('user_id', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"messeage": "Account creation failed","cause": "required user_id and password"}), 400

    if username in users:
        return jsonify({"message": "Account creation failed","cause": "already same user_id is used"}), 400
    # user_id は 6~20字
    # password は 8~20字 半角英数記号(空白と制御コードを除くASCII文字)
    if not 6 <= len(username) <= 20:
        return jsonify({"message": "Account creation failed","cause": "user_id must be 6-20 characters"}), 400
    if not 8 <= len(password) <= 20:
        return jsonify({"message": "Account creation failed","cause": "password must be 8-20 characters"}), 400
    if not all([c.isalnum() or c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" for c in password]):
        return jsonify({"message": "Account creation failed","cause": "password must be alphanumeric"}), 400
    user_id = username
    users[user_id] = {
        "user_id": user_id,
        "password": password,
        "user_name": username,
        "comment": ""
    }

    return jsonify({"message": "Account successfully created", "user": {"user_id": user_id, "nickname": username}}), 201

@app.route('/login', methods=['POST'])
def login():
    return authenticate(request)

@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    auth = authenticate(request)
    if not isinstance(auth, dict):
        return auth

    if user_id not in users:
        return jsonify({ "message":"No User found" }), 404

    if users[user_id]["comment"] != "":
        return jsonify({"message": "User details by user_id", "user": {"user_id": user_id, "nickname": users[user_id]["user_name"], "comment": users[user_id]["comment"]}}), 200
    else:
        return jsonify({"message": "User details by user_id", "user": {"user_id": user_id, "nickname": users[user_id]["user_name"]}}), 200

@app.route('/users/<user_id>', methods=['PATCH'])
def update_user(user_id):
    auth = authenticate(request)
    if not isinstance(auth, dict):
        return auth
    # 認証と異なるuser_idの場合はエラー
    if user_id != auth["user_id"]:
        return jsonify({"message": "No Permission for Update"}), 400
    if user_id not in users:
        return jsonify({ "message":"No User found" }), 404

    if 'nickname' in request.json:
        users[user_id]['user_name'] = request.json['user_name']
    if 'comment' in request.json:
        users[user_id]['comment'] = request.json['comment']
    if 'nickname' not in request.json and 'comment' not in request.json:
        return jsonify({"message": "User updation failed", "cause": "required nickname or comment"}), 400
    if 'user_id' in request.json or 'password' in request.json:
        return jsonify({"message": "User updation failed", "cause": "not updatable user_id and password"}), 400
    return jsonify({"msg": "User updated"}), 200

@app.route('/close', methods=['POST'])
def delete_user():
    auth = authenticate(request)
    if not isinstance(auth, dict):
        return auth

    user_id = auth["user_id"]

    if user_id not in users:
        return jsonify({"msg": "User not found"}), 404

    del users[user_id]

    return jsonify({{"message": "Account and user successfully removed" }}), 200

def authenticate(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        return jsonify({"message": "Authentication Failed"}), 401

    try:
        auth_base64 = auth_header.split(' ')[1]
        auth_decoded = base64.b64decode(auth_base64).decode('utf-8')
        user_id, password = auth_decoded.split(':')

        if user_id not in users or users[user_id]['password'] != password:
            return jsonify({"message": "Authentication Failed"}), 401

        return {"user_id": user_id}
    except Exception as e:
        return jsonify({"message": "Authentication Failed"}), 401

if __name__ == '__main__':
    app.run()