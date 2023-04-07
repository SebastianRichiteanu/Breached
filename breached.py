from flask import Flask, render_template, request, url_for, redirect, jsonify, make_response, flash, send_from_directory, send_file
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
app.config["JWT_COOKIE_CSRF_PROTECT"] = False


user_schema = {
    'username': str,
    'password': str
}
 
post_schema = {
    'id': int,
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
            response = redirect('/')
            set_access_cookies(response=response, encoded_access_token=access_token)
            return response
        else:
            return render_template('auth/login.html', message='Username or password incorrect!')
    else:
        return render_template('auth/login.html')

@app.route('/logout', methods=["GET"])
@jwt_required()
def logout():
    response = redirect('/')
    unset_jwt_cookies(response)
    return response
    

@app.route("/posts", methods=["GET"])
def posts():
    posts = posts_collection.find()
    return render_template('posts.html', posts=posts)

@app.route("/post/<post_id>", methods=["GET"])
@jwt_required(optional=True)
def get_template(post_id):
    post = posts_collection.find_one({"id":int(post_id)})
    if post:
        current_user = get_jwt_identity() 
        owner = False
        if post["user"] == current_user:
            owner = True
        return render_template('/post/get.html', post=post, owner=owner)

    return jsonify({'msg': 'NU'}), 404


@app.route("/post/create", methods=["GET", "POST"])
@jwt_required()
def create_post():
    if request.method == 'POST':
        current_user = get_jwt_identity() 

        if current_user:
            title = request.form["title"]
            if posts_collection.find_one({"title":title}) != None:
                return render_template('post/create.html', message='Post already exists!')

            content = request.form["content"]
            post_id = posts_collection.count_documents({})+1
            app.logger.debug(post_id)
            user_post = {"id": post_id, "user" : current_user,  "title": title, "content": content}
            posts_collection.insert_one(user_post)
            return render_template('post/create.html', message='Sucessfully created post!')

    return render_template('post/create.html')


@app.route("/post/delete/<post_id>", methods=["GET"])
@jwt_required()
def delete_template(post_id):
    current_user = get_jwt_identity()
    
    if current_user:
        post = posts_collection.find_one({"id":int(post_id)})
        if post["user"] == current_user:
            posts_collection.delete_one(post)
            return redirect("/posts")
    return redirect("/login")
            

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
            file.save(os.path.join(app.config['PROFILE_PICTURES'], current_user+'.jpg'))
        response = redirect(request.url)  
    else:
        full_filename = "/photos?photo="+current_user+".jpg"
        response = make_response(render_template('profile.html', user_image= full_filename))


    return response

@app.route("/photos", methods=["GET"])
def get_photo():
    path = request.args.get("photo")
    return send_file(app.config["PROFILE_PICTURES"] +'/' +path)

app.add_url_rule(
    "/photos", endpoint="get_photo", build_only=True
)

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

