from flask import Flask, render_template, render_template_string, request, url_for, redirect, jsonify, make_response, send_from_directory, send_file
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
# ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_EXTENSIONS = {'jpg'}

app = Flask(__name__)

app.config['PROFILE_PICTURES'] = PROFILE_PICTURES

client = MongoClient('localhost', 27017)
db = client.flask_db

users_collection = db.users
posts_collection = db.posts
comments_collection = db.comms

try:
    posts_increment = posts_collection.find_one(sort=[("id", -1)])["id"]
except:
    posts_increment = 0

try:
    comm_increment = comments_collection.find_one(sort=[("id", -1)])["id"]
except:
    comm_increment = 0

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

comment_schema = {
    'id': int,
    'post_id':int,
    'user': str,
    'content': str,
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

@app.route("/post", methods=["GET"])
@jwt_required(optional=True)
def get_template():
    post_id = request.args.get("id")
    post = posts_collection.find_one({"id":int(post_id)})
    if post:
        current_user = get_jwt_identity() 
        owner = False
        if post["user"] == current_user:
            owner = True
        comments = comments_collection.find({"post_id":int(post_id)})
        return render_template('/post/get.html', post=post, owner=owner, comments=comments)

    return redirect("/posts")

@app.route("/postcomment", methods=["POST"])
@jwt_required()
def post_comment():
    global comm_increment
    if request.method == 'POST':
        current_user = get_jwt_identity()
        if current_user:
            content = request.form['content']
            post_id = request.form['post_id']
            comm_increment += 1
            comments_collection.insert_one({'id':comm_increment, 'user': current_user, 'content': content, 'post_id': int(post_id)})
            response = redirect("/post?id="+str(post_id))
        else:
            response = redirect("/login")
    else:
        response = redirect("/")
    
    return response

@app.route("/deletecomment", methods=["GET"])
@jwt_required()
def delete_comment():
    current_user = get_jwt_identity()
    comment_id = request.args.get("id")
    if current_user:
        try:
            comment = comments_collection.find_one({"id":int(comment_id)})
            comments_collection.delete_one(comment)
        except:
            return render_template_string("Error while trying to delete " + comment_id + "!")
            
    return render_template_string("Deleted " + comment_id + "!")


@app.route("/post/create", methods=["GET", "POST"])
@jwt_required()
def create_post():
    global posts_increment
    if request.method == 'POST':
        current_user = get_jwt_identity() 

        if current_user:
            title = request.form["title"]
            if posts_collection.find_one({"title":title}) != None:
                return render_template('post/create.html', message='Post already exists!')

            content = request.form["content"]
            posts_increment += 1
            user_post = {"id": posts_increment, "user" : current_user,  "title": title, "content": content}
            posts_collection.insert_one(user_post)
            return render_template('post/create.html', message='Sucessfully created post!')

    return render_template('post/create.html')


@app.route("/post/delete", methods=["GET"])
@jwt_required()
def delete_template():
    current_user = get_jwt_identity()
    post_id = request.args.get("id")
    if current_user:
        try:
            comments = comments_collection.find({"post_id":int(post_id)})
            post = posts_collection.find_one({"id":int(post_id)})
            comments_collection.delete_many(comments)
            posts_collection.delete_one(post)
        except:
            return render_template_string("Error while trying to delete " + post_id + "!")
            
    return render_template_string("Deleted " + post_id + "!")
            

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
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
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
    try:
        return send_file(app.config["PROFILE_PICTURES"] +'/' +path)
    except:
        return make_response("<pre>THIS\n"+"IS\n"+"WHERE\n"+"YOUR\n"+"PROFILE\n"+"PICTURE\n"+"WOULD\n"+"BE\n"+"IF\n"+"YOU\n"+"HAD\n"+"ONE\n"+"</pre>")

app.add_url_rule(
    "/photos", endpoint="get_photo", build_only=True
)


@app.route("/")
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

