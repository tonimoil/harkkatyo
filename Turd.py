import os
from flask import Flask, send_file, request, redirect, url_for, make_response
from flask_login import LoginManager, current_user, login_user, UserMixin, logout_user, login_required
import yaml
import queue
import subprocess
import threading
import time
import sys #logaamista varten
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Load configuration file
configuration = {}

with open("app.config.yaml") as stream:
    configuration = yaml.load(stream)

app = Flask(__name__)
app.secret_key = 'xyz'

## Luodaan tietokanta käyttäjien seuraamista varten sekä
## Flask-Loginin toimintaa varten
app.config['SQLACLHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password + 'pippuri')

    def check_password(self, password):
        return check_password_hash(self.password_hash,password + 'pippuri')

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

## Hard koodataan käyttäjät tällä tavalla
db.create_all()

user1 = User(username='lion')
user1.set_password('1')
user2 = User(username="sue")
user2.set_password('2')
user3 = User(username="sam")
user3.set_password('3')
db.session.add(user1), db.session.add(user2), db.session.add(user3)
db.session.commit()

# Some global variables
bad_file_log = set()            # Set of known dangerous files in service
suspicious_file_log = set()     # Set of unchecked files
shared_files = {}               # Set of files that are shared to all users
checker_queue = queue.LifoQueue(1000)   # Last-in-First-out queue for storing unchecked files

def checkerLoop(queue):
    """ This checks each incoming file. If they are not PNG files they
        get deleted. This will protect against uploading HTML and XSS

        This will be run as a background thread
        """
    while True:
        filename = queue.get()
        res = subprocess.run(
            "file %s" % filename,
            shell=True,
            timeout=15,
            stdout=subprocess.PIPE)
        res = res.stdout.decode('utf-8')
        print(res)
        if not ("PNG image data" in res
                or "JPEG image data" in res):
            os.remove(filename)
            bad_file_log.add(filename)
        else:
            suspicious_file_log.remove(os.path.basename(filename))


# Start the background checker thread
t = threading.Thread(target=checkerLoop, args=(checker_queue, ))
t.start()

@app.route('/login')
def login():
    """ This route allows user to log in

        If user gives a filename that file is sent to user, otherwise
        user is shown a file listing
    """
    if current_user.is_authenticated:
        return redirect('/user_content')

    username = request.args.get('user')
    password = request.args.get('password')
    if username and password:
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):
            login_user(user)
            resp = make_response("""
              <!doctype html>
              <title>You are logged in</title>
              <h1>Login successful</h1>
              You can now <a href="/user_content">check your files</a>
              """)

            # Create directory for user files
            path = configuration['web_root'] + "/" + current_user.username
            if not os.path.exists(path):
                os.makedirs(path)
            
            return resp

        else:
            return """
            <!doctype html>
            <title>Login failed</title>
            <h1>Login failed!</h1>
            <form>
              <input type=text name=user>
              <input type=password name=password>
              <input type=submit value="Log In">
            </form>
            """

    else:
        return '''
        <!doctype html>
        <title>Log in</title>
        <h1>System log in</h1>
        <form>
          <input type=text name=user>
          <input type=password name=password>
          <input type=submit value="Log In">
        </form>
        '''


@app.route('/logout')
@login_required
def logout():
    """ This will log out the current user """
    username = current_user.username
    logout_user()
    resp = make_response('''
            <!doctype html>
            <title>Log out</title>
            <h1>System log out</h1>
            User %s has been logged out
            ''' % username)
    return resp


def checkPath(path):
    """ This will check and prevent path injections """
    if "../" in path:  #
        raise Exception("Possible Path-Injection")

@app.route('/share_file')
@login_required
def share_file():
    """ This route handler will allow users to share files
    """

    username = current_user.username
    if not username: return redirect(url_for('login'))
    path = configuration['web_root'] + "/" + username

    user_file = request.args.get('file')

    checkPath(path+"/"+user_file)

    shared_files[user_file] = path+"/"+user_file

    return '''
        <!doctype html>
        <title>File shared</title>
        <h1>File shared: %s</h1>
        <a href="/user_content">back to files</a>
        <br>
        <a href="/logout">log out</a>
        ''' % user_file


@app.route('/delete_file')
@login_required
def delete_file():
    """ This route handler will allow users to delete files.

        If the file is '*' all user files are deleted
    """

    username = current_user.username
    if not username: return redirect(url_for('login'))
    path = configuration['web_root'] + "/" + username

    user_file = request.args.get('file')

    if user_file == '*':
        files = os.listdir(path)
        for file in files:
            os.remove(path + '/' + file)
        return '''
        <!doctype html>
        <title>File deleted</title>
        <h1>File Deleted: %s</h1>
        <a href="/user_content">back to files</a>
        <br>
        <a href="/logout">log out</a>
        ''' % files
    else:
        os.remove(configuration['web_root'] + "/" + username + "/" + user_file)
        return '''
        <!doctype html>
        <title>File deleted</title>
        <h1>File Deleted: %s</h1>
        <a href="/user_content">back to files</a>
        <br>
        <a href="/logout">log out</a>
        ''' % user_file


@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    """ This route handler will allow users to upload files

        If the request method is POST file is being uploaded. Otherwise
        we show a file upload prompt
    """
    username = current_user.username
    if not username: return redirect(url_for('login'))
    path = configuration['web_root'] + "/" + username

    if request.method == 'POST':
        if 'file' not in request.files:
            raise Exception('No file part')
            return redirect(request.url)
        thefile = request.files['file']
        if thefile.filename == '':
            raise Exception('No selected file')
            return redirect(request.url)
        if thefile:
            checkPath(thefile.filename)
            target_path = path + '/' + thefile.filename

            # Mark the fle initially as suspicious. The checker thread will
            # remove this flag
            suspicious_file_log.add(thefile.filename)

            thefile.save(target_path)
            thefile.close()

            # The checker is slow so we run it in a background thread
            # for better user experience
            checker_queue.put(target_path)
            return redirect(url_for('serve_file'))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    <br>
    <a href="/logout">log out</a>
    '''


@app.route('/user_content')
@login_required
def serve_file():
    """ This route allows fetching user files

        If user gives a filename that file is sent to user, otherwise
        user is shown a file listing
    """
    username = current_user.username
    if not username: return redirect(url_for('login'))

    user_file = request.args.get('file')
    if user_file:
        shared = shared_files.get(user_file)
        if shared:
            return send_file(shared)
        else:
            path = configuration['web_root'] + '/' + username + "/" + user_file
            checkPath(path)
            return send_file(path)
    else:
        files = os.listdir(configuration['web_root'] + "/" + username)
        link_list = "\n".join([
            """<a href='/user_content?file=%s'>%s</a>
               <a href='/delete_file?file=%s'> (delete)</a>
               <a href='/share_file?file=%s'> (share)</a>
            """
            % (f, f, f, f) for f in files
            if not f in suspicious_file_log  # Remove suspicious files
        ])

        shared_list = "\n".join([
            """<a href='/user_content?file=%s'>%s</a>
            """
            % (f,f) for f in shared_files
            if not f in suspicious_file_log  # Remove suspicious files
        ])

        rejects = ""
        if bad_file_log:
            rejects = ("<h1>Some files were rejected</h1>"
                       "<p>" + "\n".join(bad_file_log) + "</p>")
        return '''
            <!doctype html>
            <title>Files:</title>
            <h1>Your files</h1>
            %s
            <p>Some files may still be uploading. Refresh the page.</p>
            <br>
            %s
            <h1>Shared files</h1>
            %s
            <h1>Upload more files</h1>
            You can upload more files <a href="/upload_file">here</a>
            </form>
            <br>
            <a href="/logout">log out</a>
            ''' % (link_list, rejects,shared_list)
