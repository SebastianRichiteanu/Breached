from flask import Flask, render_template, request, url_for, redirect, jsonify, make_response, flash
from pymongo import MongoClient
import hashlib
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, set_access_cookies, unset_jwt_cookies
from werkzeug.utils import secure_filename
import datetime
import hashlib
import urllib
import secrets
import os

PROFILE_PICTURES = os.path.join('static', 'profile_pictures')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

app.config['PROFILE_PICTURES'] = PROFILE_PICTURES

client = MongoClient('localhost', 27017)
db = client.flask_db

users_collection = db.users
posts_collection = db.posts

jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'secret' #secrets.token_hex(16)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config["JWT_COOKIE_SECURE"] = True


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
            # response = make_response(render_template('index.html', message='Login successful!'))
            response = redirect('/')
            set_access_cookies(response=response, encoded_access_token=access_token)
            # response.set_cookie('access_token_cookie', access_token)
            return response
        else:
            return render_template('auth/login.html', message='Username or password incorrect!')
    else:
        return render_template('auth/login.html')

@app.route('/logout', methods=["GET"])
@jwt_required()
def logout():
    # response = make_response(render_template('index.html'))
    response = redirect('/')
    unset_jwt_cookies(response)
    return response
    

@app.route("/post/create", methods=["GET", "POST"])
@jwt_required()
def create_post():
    if request.method == 'POST':
        current_user = get_jwt_identity() 

        #sebik bosule sterge user_from_db si foloseste current_user ca e fix acelasi lucru. pui current_user!=None ca sa verifici

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
    

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/profile", methods=["GET", "POST"])
@jwt_required(optional=True)
def my_profile():
    current_user = get_jwt_identity()
    if current_user==None:
        return redirect("/login")
    if request.method== "POST":

        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # filename = secure_filename(file.filename) # removes ../

            file.save(os.path.join(app.config['PROFILE_PICTURES'], current_user+'.jpg'))
        response = redirect(request.url)  
    else:
        full_filename = os.path.join(app.config['PROFILE_PICTURES'], current_user+'.jpg') #needs file type checking; maybe some searching in the with the user's name
        response = make_response(render_template('profile.html', user_image= full_filename))


    return response

@app.route("/photos/<user>", methods=["GET"])
def get_photo(user):
    full_filename = os.path.join(app.config['PROFILE_PICTURES'], user+'.jpg')
    response = make_response()

@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html') 

@app.context_processor
@jwt_required(optional=True)
def inject_user():
    current_user = get_jwt_identity()
    if current_user==None:
        current_user=""
    return dict(username=current_user)

