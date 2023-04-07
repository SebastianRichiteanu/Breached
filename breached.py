from flask import Flask, render_template, request, url_for, redirect, jsonify, make_response
from pymongo import MongoClient
import hashlib
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import datetime
import hashlib
import urllib
import secrets

app = Flask(__name__)

client = MongoClient('localhost', 27017)
db = client.flask_db

users_collection = db.users
posts_collection = db.posts

jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'secret' #secrets.token_hex(16)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']


user_schema = {
    'username': str,
    'password': str
}
 
post_schema = {
    'title': str,
    'content': str,
    'user': str
}

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        # maybe encrypt password
        user = users_collection.find_one({"username":username})
        if not user:
            users_collection.insert_one({'username': username, 'password': password})
            return render_template('auth/register.html', message='Sucessfully registered! You can now log in.')
        else:
            return render_template('auth/register.html', message='User already exists!')
    else:
        return render_template('auth/register.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        user_from_db = users_collection.find_one({"username":username})
        if user_from_db and password == user_from_db["password"]:
            access_token = create_access_token(identity=username)
            response = make_response(render_template('auth/login.html', message='Login successful!'))
            response.set_cookie('access_token_cookie', access_token)
            return response
        else:
            return render_template('auth/login.html', message='Username or password incorrect!')
    else:
        return render_template('auth/login.html')

@app.route('/logout', methods=["GET"])
@jwt_required()
def logout():
    response = make_response(render_template('index.html'))
    response.set_cookie('access_token_cookie', '')
    return response
    

@app.route("/post/create", methods=["GET", "POST"])
@jwt_required()
def create_post():
    if request.method == 'POST':
        current_user = get_jwt_identity() 
        user_from_db = users_collection.find_one({'username' : current_user})
        
        if user_from_db:
            title = request.form["title"]
            content = request.form["content"]

            user_post = {'user' : user_from_db["username"],  "post": title, "content": content}
            post = posts_collection.find_one(user_post) 
            
            if not post:
                posts_collection.insert_one(user_post)
                return render_template('post/create.html', logged_in = 1)
            else: 
                return render_template('post/create.html', logged_in = 2)
    else:
        return render_template('post/create.html')

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
            return jsonify({'msg': 'Post Deleted Sucessfully'}), 404
        else: return jsonify({'msg': 'Post not exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404

@app.route('/', methods=['GET'])
def index():
    current_user = ""
    try: 
        current_user = get_jwt_identity()
    except:
        return render_template('index.html')

    return render_template('index.html') 

@app.context_processor
@jwt_required
def inject_user():
    try: 
        current_user = get_jwt_identity()
    except:
        return dict(username="")
    return dict(username=current_user)

