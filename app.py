from flask import Flask, render_template, session, redirect, url_for, request, flash
from werkzeug.security import check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "lkasjdlkasjlkfjaps;"

conn_users = sqlite3.connect(
    r'C:\Users\Taimur Adam\Desktop\Adam Sugar\website\data\databases\users.sqlite3', check_same_thread=False)
cur_users = conn_users.cursor()

cur_users.executescript('''

CREATE TABLE IF NOT EXISTS users(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE, username TEXT UNIQUE, password TEXT, role INTEGER);

''')

application=app 

@app.route('/')
def index():
    if "user" in session:
        return render_template('base.html')
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            cur_users.execute(
                'SELECT password FROM users WHERE users.username = (?)', (username,))
            encrypted_password = cur_users.fetchone()[0]
        except:
            flash("Incorrect username.", category='error')
            return render_template('login.html')

        if check_password_hash(encrypted_password, password):
            session['user'] = username
            flash('Login successful.', category='success')
            cur_users.execute(
                'SELECT role FROM users WHERE users.username = ?', (username,))
            session['role'] = cur_users.fetchone()[0]

        else:
            flash('Incorrect password.', category='error')
            return render_template('login.html')

        return redirect(url_for('index'))
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():

    if "user" in session:
        session.pop('user')
        session.pop('role')
        flash('Successfully logged out.', category='success')
        return redirect(url_for('login'))
    else:
        flash('Please sign in.')
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()
