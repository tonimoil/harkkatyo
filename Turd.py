import os
from flask import Flask, send_file, request, redirect, url_for, make_response, render_template_string
from flask_login import LoginManager, current_user, login_user, UserMixin, logout_user, login_required
import yaml
import queue
import subprocess
import threading
import magic
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import math

# Apufunktiota XSS-hyökkäyksiä varten, muutetaan näiden avulla nimet
# numeroiksi, jolloin <a href=user_input> tyyppisiä hyökkäyksiä ei voida
# toteuttaa
def convertToNumber(s):
    return int.from_bytes(s.encode(), 'little')

def convertFromNumber(n):
    return n.to_bytes(math.ceil(n.bit_length()/8), 'little').decode()

# Load configuration file
configuration = {}

with open("app.config.yaml") as stream:
    configuration = yaml.load(stream)

app = Flask(__name__)
app.secret_key = 'xyz'

# Luodaan tietokanta käyttäjien seuraamista varten sekä
# Flask-Loginin toimintaa varten
app.config['SQLACLHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)

# Upload kansion perustaminen
if not os.path.exists(os.path.abspath(configuration['upload'])):
    os.makedirs(os.path.abspath(configuration['upload']))

# Flaskin loginia varten
login_manager = LoginManager(app)

# Tehdään luokka käyttäjille, joka on peritty flaskin luokasta UserMixin
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String())
    home_folder = db.Column(db.String(), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password + 'pippuri')

    def check_password(self, password):
        return check_password_hash(self.password_hash,password + 'pippuri')

    # Asetetaan tietokantaan käyttäjälle polku
    # Voidaan käyttää vertailussa apuna
    def set_home_folder(self):
        self.home_folder = str(os.path.abspath(configuration['web_root'] + '/' + self.username))

#Perustetaan tietokanta
db.create_all()

#Flaskin loginia varten
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

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
        # filename[0] == upload path
        # filename[1] == target path
        # filename[2] == filename
        detected = magic.detect_from_filename(filename[0])
        if not("image/png" in detected
            or "image/jpeg" in detected):
            os.remove(filename[0])
            bad_file_log.add(filename[2])
        else:
            # Poistetaan hämärät tiedostot logista ja siirretään ne
            # Upload kansiosta käyttäjän kansioon
            suspicious_file_log.remove(os.path.basename(filename[0]))
            os.rename(filename[0], filename[1])

# Start the background checker thread
t = threading.Thread(target=checkerLoop, args=(checker_queue, ))
t.start()

@app.route('/sign_up')
def sign_up():
    "This route allows user to create an account"
    if current_user.is_authenticated:
        return redirect('/user_content')

    username = request.args.get('username')
    password = request.args.get('password')
    if username and password:
        #Sallitaan nimissä vain aakkoset
        if username.isalpha():
            #Tarkistetaan, että onko jo olemassa käyttäjä
            user = User.query.filter_by(username = username).first()

            if user:
                return'''
                <!doctype html>
                <title>Sign up</title>
                <h1>Sign up</h1>
                <h3>Username already in use!</h3>
                <form>
                    <input type=text name=username>
                    <input type=password name=password>
                    <input type=submit value="Sign Up">
                </form>
                '''
            # Luodaan uusi käyttäjä
            new_user = User(username = username)
            db.session.add(new_user)
            new_user.set_password(password)
            new_user.set_home_folder()
            db.session.commit()

            return redirect('/login')
        else:
            return '''
            <!doctype html>
            <title>Sign up</title>
            <h1>Sign up</h1>
            <h3>Only alphabets allowed in the username!</h3>
            <form>
                <input type=text name=username>
                <input type=password name=password>
                <input type=submit value="Sign Up">
            </form>
            '''

    else:
        return '''
        <!doctype html>
        <title>Sign up</title>
        <h1>Sign up</h1>
        <form>
            <input type=text name=username>
            <input type=password name=password>
            <input type=submit value="Sign Up">
        </form>
        '''

@app.route('/login')
def login():
    """ This route allows user to log in
        If user gives a filename that file is sent to user, otherwise
        user is shown a file listing
    """
    # Jos käyttäjä on kirjautunut, niin ohjataan user_contentiin
    if current_user.is_authenticated:
        return redirect('/user_content')

    username = request.args.get('user')
    password = request.args.get('password')
    
    # Jos molemmat syötetty, niin katsotaan, että onko salasana ja käyttäjätunnus
    # yhdenmukaiset
    if username and password:
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):

            # Kirjataan onnistunut käyttäjä flaskin-loginiin
            login_user(user)

            # Tarkistetaan, että onko käyttäjänimessä ainostaan aakkosia
            # -> laiska tapa estää rikkinäiset tiedostopolut
            # Kirjataan käyttäjä ulos, mikä on muuta kuin aakkosia
            if not (current_user.username).isalpha():
                username = current_user.username
                logout_user()
                return render_template_string('''
                    <!doctype html>
                    <title>Log out</title>
                    <h1>Your username can contain only letters</h1>
                        User {{username}} has been logged out
                    ''', username = username)

            resp = make_response("""
              <!doctype html>
              <title>You are logged in</title>
              <h1>Login successful</h1>
              You can now <a href="/user_content">check your files</a>
              """)

            # Create directory for user files
            if not os.path.exists(current_user.home_folder):
                os.makedirs(current_user.home_folder)
            
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
    return render_template_string(
        '''
            <!doctype html>
            <title>Log out</title>
            <h1>System log out</h1>
            User {{username}} has been logged out
        ''', username = username
    )


def checkPath(path):
    """ This will check and prevent path injections """
    if not os.path.abspath(path).startswith(current_user.home_folder):
        raise Exception("Possible Path-Injection")

@app.route('/share_file')
@login_required
def share_file():
    """ This route handler will allow users to share files
    """
    path = current_user.home_folder

    # Muutetaan syötetty numero jonoksi
    user_file = convertFromNumber(int(request.args.get('file')))

    # Haetaan jaetuista tiedostoista käyttäjän antama tiedosto
    shared = shared_files.get(user_file)

    # Jos tiedostoa ei ole jo jaettu, niin jaetaan annettu tiedosto
    # Käyttäjä voi jakaa vain omia tiedostoja, sillä tiedoston täytyy
    # olla @ current_user.home_folder
    if not shared:
        path = os.path.join(current_user.home_folder, user_file)
        checkPath(path)
        shared_files[user_file] = path
        return render_template_string(
        '''
        <!doctype html>
        <title>File shared</title>
        <h1>File shared: {{user_file}}</h1>
        <a href="/user_content">back to files</a>
        <br>
        <a href="/logout">log out</a>
        ''', user_file=user_file)
    # Jos saman niminen tiedosto on jo jaettu, niin käyttäjää pyydetään
    # nimeämään tiedosto uudelleen
    # Tämä tehty osittain alkuperäisessä ohjelmassa olevan bugin takia
    else:
        return render_template_string(
        '''
        <!doctype html>
        <title>File share failed</title>
        <h1>File with this name has already been shared:{{user_file}}</h1>
        <h3>Please rename your file before sharing!</h3>
        <a href="/user_content">back to files</a>
        <br>
        <a href="/logout">log out</a>
        ''', user_file=user_file)


@app.route('/delete_file')
@login_required
def delete_file():
    """ This route handler will allow users to delete files.
        If the file is '*' all user files are deleted
    """

    username = current_user.username
    if not username: return redirect(url_for('login'))

    # Jos argumenttina on *, niin poistetaan kaikki tiedostot
    # Poistetaan jaetut tiedostot myös jaettujen listalta
    # Mikäli joku on jo jakanut saman nimisen tiedoston, niin
    # sitä ei kuitenkaan poisteta
    if request.args.get('file') == '*':
        files = os.listdir(current_user.home_folder)
        for file in files:
            path = os.path.join(current_user.home_folder, file)
            checkPath(path)
            os.remove(path)

            shared = shared_files.get(file)
            if shared == path:
                shared_files.pop(file)

        return render_template_string('''
        <!doctype html>
        <title>File deleted</title>
        <h1>File Deleted: {{files}}</h1>
        <a href="/user_content">back to files</a>
        <br>
        <a href="/logout">log out</a>
        ''', files = files)
    else:
        # Jos argumenttina on jokin muu luku, niin poistetaan se
        # käyttäjän kansioista. Tähän pitäisi lisätä try, except rakenne,
        # mutta ohjelma kyllä toimii, jos sitä ei yritetä käyttää väärin
        user_file = convertFromNumber(int(request.args.get('file')))
        path = os.path.join(current_user.home_folder, user_file)
        checkPath(path)
        os.remove(path)
        shared = shared_files.get(user_file)
        if shared == path:
            shared_files.pop(user_file)
        return render_template_string('''
        <!doctype html>
        <title>File deleted</title>
        <h1>File Deleted: {{user_file}}</h1>
        <a href="/user_content">back to files</a>
        <br>
        <a href="/logout">log out</a>
        ''', user_file = user_file)


@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    """ This route handler will allow users to upload files
        If the request method is POST file is being uploaded. Otherwise
        we show a file upload prompt
    """
    username = current_user.username
    if not username: return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            raise Exception('No file part')
            return redirect(request.url)
        thefile = request.files['file']
        if thefile.filename == '':
            raise Exception('No selected file')
            return redirect(request.url)
        if thefile:
            filename = secure_filename(thefile.filename)

            # Kokeillaan viedä tiedosto tietokantaan
            # secure_filename muuttaa tiedoston nimen esim. _ tyhjäksi
            # minkä vuoksi pyydetään käyttäjää nimeämään tiedosto uudelleen
            # mikäli se ei ole kelvollinen
            try:
                upload_path = os.path.abspath(os.path.join(configuration['upload'], filename))
                target_path = os.path.abspath(os.path.join(current_user.home_folder, filename))
                checkPath(target_path)
                
                # Jos kaikki on ok, niin ladataan tiedosto palvelimelle
                # Upload kansioon, johon käyttäjillä ei ole pääsyä
                if upload_path.startswith(os.path.abspath(configuration['upload'])):
                    suspicious_file_log.add(filename)
                    thefile.save(upload_path)
                    thefile.close()
            except:
                return '''
                <!doctype html>
                <title>Upload new File</title>
                <h1>Upload new File</h1>
                <h3>Please rename the file!</h3>
                <form method=post enctype=multipart/form-data>
                <input type=file name=file>
                <input type=submit value=Upload>
                </form>
                <br>
                <a href="/logout">log out</a>
                '''

            # The checker is slow so we run it in a background thread
            # for better user experience
            checker_queue.put([upload_path, target_path, filename])
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

# Apufunktio jaettujen tiedostojen listan luomiseen
def luoJaettu():
    return render_template_string('''
        {% for x in tiedostot %}
            {% if not x in suspicious_file_log %}
                <a href='/user_content?file={{convertToNumber(x)}}'>{{x}}</a>
            {% endif %}
        {% endfor %}
    ''', tiedostot=shared_files, suspicious_file_log=suspicious_file_log, convertToNumber = convertToNumber)

# Apufunktio kiellettyjen tiedostojen listaamista varten
def luoKielletyt():
    return render_template_string('''
        <h1>Some files were rejected</h1>
        {% for x in tiedostot %}
            \n
            <p>{{x}}</p>
        {% endfor %}
    ''', tiedostot = bad_file_log)

# Apufunktio omien tiedostojen näyttämistä varten
def luoOmat(tiedostot):
    return render_template_string('''
        {% for x in tiedostot %}
            {% if not x in suspicious_file_log %}
                <a href='/user_content?file={{convertToNumber(x)}}'>{{x}}</a>
                <a href='/delete_file?file={{convertToNumber(x)}}'> (Delete)</a>
                <a href='/share_file?file={{convertToNumber(x)}}'> (Share)</a>
            {% endif %}
        {% endfor %}
    ''', tiedostot=tiedostot, suspicious_file_log=suspicious_file_log, convertToNumber=convertToNumber)

@app.route('/user_content')
@login_required
def serve_file():
    """ This route allows fetching user files
        If user gives a filename that file is sent to user, otherwise
        user is shown a file listing
    """
    username = current_user.username
    if not username: return redirect(url_for('login'))
    
    try:
        user_file = convertFromNumber(int(request.args.get('file')))
    except:
        user_file = None

    if user_file:
        shared = shared_files.get(user_file)
        if shared:
            return send_file(shared)
        else:
            path = os.path.join(current_user.home_folder, user_file)
            checkPath(path)
            return send_file(path)
    else:
        files = os.listdir(current_user.home_folder)
        link_list = luoOmat(files)

        shared_list = luoJaettu()

        rejects = ""
        if bad_file_log:
            rejects = luoKielletyt()

        return render_template_string('''
            <!doctype html>
            <title>Files:</title>
            <h1>Your files</h1>
            {{link_list | safe}}
            <p>Some files may still be uploading. Refresh the page.</p>
            <br>
            {{rejects | safe}}
            <h1>Shared files</h1>
            {{shared_list | safe}}
            <h1>Upload more files</h1>
            You can upload more files <a href="/upload_file">here</a>
            </form>
            <br>
            <a href="/logout">log out</a>
            ''', link_list=link_list, rejects=rejects,shared_list=shared_list)