import hashlib
import secrets
import time

from dataset import Table
from flask import Flask, render_template, request, redirect, session, url_for, flash
import dataset

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

db = dataset.connect('sqlite:///mydatabase.db')
offer_table: Table = db['offer']
user_table: Table = db['user']
artifacts_table: Table =db['artifacts']


# table.insert(dict(user='John Doe', price='7000 C'))
# table.insert(dict(user='Jane Doe', price='6000 C'))

def get_pw_hash(pw: str, salt: str):
    return hashlib.sha512((pw + salt).encode()).hexdigest()


@app.route('/')
def index():
    offers = list(offer_table.all())

    return render_template('index.html', offers=offers)


# register
@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password1 = request.form['password1']
    password2 = request.form['password2']


    if (user_table.find_one(username=username)):
        flash('Username already used', 'error')
        return redirect('/register')


    if (password1 == password2):
        session['username'] = username

        salt = secrets.token_hex(20)
        password_hash = get_pw_hash(password1, salt)

        user_table.insert(dict(
            username=username,
            password=password_hash,
            salt=salt,
            created=time.time(),
            updated=time.time()
        ))

        return redirect('/')
    else:
        return 'Unvalid arguments', 401


# Create Offer
@app.route('/create_offer')
def create_offer():
    return render_template('create_offer.html')


@app.route('/create_offer', methods=['POST'])
def offer_post():
    flash('posted new offer')
    offer_orb_type = request.form['offer_orb_type']
    offer_orb_lvl = request.form['offer_orb_lvl']
    offer_orb_amount = request.form['offer_orb_amount']
    offer_bluecrystal_type = request.form['offer_bluecrystal_type']
    offer_bluecrystal_lvl = request.form['offer_bluecrystal_lvl']
    offer_bluecrystal_amount = request.form['offer_bluecrystal_amount']
    offer_tetrahedron_type = request.form['offer_tetrahedron_type']
    offer_tetrahedron_lvl = request.form['offer_tetrahedron_lvl']
    offer_tetrahedron_amount = request.form['offer_tetrahedron_amount']

    demand_orb_type = request.form['demand_orb_type']
    demand_orb_lvl = request.form['demand_orb_lvl']
    demand_orb_amount = request.form['demand_orb_amount']
    demand_bluecrystal_type = request.form['demand_bluecrystal_type']
    demand_bluecrystal_lvl = request.form['demand_bluecrystal_lvl']
    demand_bluecrystal_amount = request.form['demand_bluecrystal_amount']
    demand_tetrahedron_type = request.form['demand_tetrahedron_type']
    demand_tetrahedron_lvl = request.form['demand_tetrahedron_lvl']
    demand_tetrahedron_amount = request.form['demand_tetrahedron_amount']


    offer_table.insert(dict(
        offer_orb_type=offer_orb_type,
        offer_orb_lvl=offer_orb_lvl,
        offer_orb_amount=offer_orb_amount,
        offer_bluecrystal_type=offer_bluecrystal_type,
        offer_bluecrystal_lvl=offer_bluecrystal_lvl,
        offer_bluecrystal_amount=offer_bluecrystal_amount,
        offer_tetrahedron_type=offer_tetrahedron_type,
        offer_tetrahedron_lvl=offer_tetrahedron_lvl,
        offer_tetrahedron_amount=offer_tetrahedron_amount,

        demand_orb_type = demand_orb_type,
        demand_orb_lvl = demand_orb_lvl,
        demand_orb_amount = demand_orb_amount,
        demand_bluecrystal_type = demand_bluecrystal_type,
        demand_bluecrystal_lvl = demand_bluecrystal_lvl,
        demand_bluecrystal_amount = demand_bluecrystal_amount,
        demand_tetrahedron_type = demand_tetrahedron_type,
        demand_tetrahedron_lvl = demand_tetrahedron_lvl,
        demand_tetrahedron_amount = demand_tetrahedron_amount,))
    return redirect('')


# Login
@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']

    user = user_table.find_one(username=username)
    password_hash = get_pw_hash(request.form['password'], user['salt'])

    if (secrets.compare_digest(password_hash, user['password'])):
        session['username'] = username
        return redirect('/')
    else:
        return 'Unvalid username password', 401


# logout
@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))

# Profil
@app.route('/profile')
def Profil():
    return render_template('profile.html')

def main():
    app.run('127.0.0.1', 8080, debug=True)


if __name__ == '__main__':
    main()