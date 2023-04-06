from flask import Flask, render_template, request, url_for, redirect, jsonify
from pymongo import MongoClient
import hashlib
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import datetime
import hashlib
import urllib
import secrets

app = Flask(__name__)

client = MongoClient('localhost', 27017, username='pompompurin', password='pompompurin')
db = client.flask_db

users_collection = db.users
posts_collection = db.posts

jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(16)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)



@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        new_user = request.get_json()
        # maybe encrypt password
        doc = users_collection.find_one({"username":new_user["username"]})
        if not doc:
            users_collection.insert_one(new_user)
            return render_template('auth/register.html', state=1)
        else:
            return render_template('auth/register.html', state=2)
    else:
        return render_template('auth/register.html', state=0)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        login_details = request.get_json()
        user_from_db = users_collection.find_one({"username":login_details["username"]})
        if user_from_db:
            if login_details["password"] == user_from_db["password"]:
                access_token = create_access_token(identity=user_from_db["username"])  # creca aici nosql
                return jsonify(access_token=access_token), 200
        return jsonify({'msg':'Username or password incorrect!'}), 401
    else:
        return render_template('auth/login.html')



@app.route("/post/create", methods=["POST"])
@jwt_required()
def create_post():
    current_user = get_jwt_identity() 
    user_from_db = users_collection.find_one({'username' : current_user})
    
    if user_from_db:
        post_details = request.get_json() 
        user_post = {'profile' : user_from_db["username"],  "post": post_details["post"]}
        post = posts_collection.find_one(user_post) 
        
        if not post:
            posts_collection.insert_one(user_post)
            return jsonify({'msg': 'Post created successfully'}), 200
        else: 
            return jsonify({'msg': 'Post already exists on your profile'}), 404
    return jsonify({'msg': 'Access Token Expired'}), 404

@app.route("/post/get", methods=["GET"])
@jwt_required()
def get_template():
    current_user = get_jwt_identity() 
    user_from_db = users_collection.find_one({'username' : current_user})
    if user_from_db:
        user_post = {'profile' : user_from_db["username"]}
        return jsonify({"docs":list(db.templates.find(user_post, {"_id":0}))}), 200

    return jsonify({'msg': 'Access Token Expired'}), 404


@app.route("/post/update", methods=["POST"])
@jwt_required()
def update_template():
    current_user = get_jwt_identity()
    user_from_db = users_collection.find_one({'username' : current_user})
    
    if user_from_db:
        post_details = request.get_json() 
        user_template = {'profile' : user_from_db["username"],  "post": post_details["post"]}
        doc = posts_collection.find_one(user_template) 

        if doc:
            doc["template"] = post_details["post"]
            posts_collection.update_one(user_template, {"$set": {"post":doc["post"]}}, upsert=False)
            return jsonify({'msg': 'Post Updated successfully'}), 200
        else: return jsonify({'msg': 'Post not exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404

@app.route("/post/delete", methods=["POST"])
@jwt_required()
def delete_template():
    current_user = get_jwt_identity()
    user_from_db = users_collection.find_one({'username' : current_user})
    
    if user_from_db:
        post_details = request.get_json() 
        user_template = {'profile' : user_from_db["username"],  "post": post_details["post"]}
        doc = posts_collection.find_one(user_template) 
        if doc:
            posts_collection.delete_one(user_template)
            print("user_template ", user_template)
            return jsonify({'msg': 'Post Deleted Sucessfully'}), 404
        else: return jsonify({'msg': 'Post not exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404

@app.route('/', methods=['GET'])
def index():
    # current_user = get_jwt_identity()
    # username = current_user["username"]
    username = ""
    return render_template('index.html', username=username)

