from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


#comment clearly so you can go back and change as needed

#initilization standard for any flask app
app = Flask(__name__)
app.secret_key = 'imthegoat'

#helper func to establish connection to DB (sql)
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

#initialize table and create user table
def init_db():
    conn = get_db_connection()

    conn.execute(''' CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE, 
    password TEXT NOT NULL)
    ''')

    # Create wallet_transactions table if not exists
    conn.execute('''
    CREATE TABLE IF NOT EXISTS wallet_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        transaction_type TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    # Create bets table for the betting system
    conn.execute('''
    CREATE TABLE IF NOT EXISTS bets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        creator_id INTEGER NOT NULL,
        opponent_id INTEGER,
        description TEXT NOT NULL,
        bet_amount REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        accepted_at DATETIME,
        resolved_at DATETIME,
        winner_id INTEGER,
        FOREIGN KEY(creator_id) REFERENCES users(id),
        FOREIGN KEY(opponent_id) REFERENCES users(id),
        FOREIGN KEY(winner_id) REFERENCES users(id)
    )
    ''')

    conn.commit()
    conn.close()

init_db()

#now connect to front end (apis to display)

#landing page
@app.route('/')
def index():
    return render_template('index.html')

#signup route
@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'] #get info from form submission

        hashed_password = generate_password_hash(password) #hash password for security 

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?,?,?)', (username, email, hashed_password))
            conn.commit()
            flash('Account created successfully! Please go to login', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists...', 'danger')
        
        finally:
            conn.close()

    return render_template('signup.html')

#login route 
@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * from users WHERE username = ? or email = ?', (username_or_email, username_or_email)).fetchone() #find relevant user
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id'] #temp info for session storage
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return(redirect(url_for('dashboard')))
        else:
            flash('Invalid credentials, try again please', 'danger')
        
    return render_template('login.html')

#dashboard/home page (with all personal betting info)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: 
        flash('Please log in first before going here.', 'warning')
        return redirect(url_for('login'))
    
    return render_template('home.html', username = session['username'])

#wallet mock
@app.route('/wallet', methods = ['GET', 'POST'])
def wallet():
    if 'user_id' not in session:
        flash('Please log in first before going here.', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    #calculate current balance by summing transactions
    balance_row = conn.execute('SELECT COALESCE(SUM(amount),0) AS balance FROM wallet_transactions WHERE user_id = ?', (session['user_id'],)).fetchone()
    balance = balance_row['balance'] if balance_row else 0

    # Handle deposit or withdrawal submissions
    if request.method == 'POST':
        transaction_type = request.form.get('transaction_type')
        try:
            amount = float(request.form.get('amount'))
        except ValueError:
            flash('Invalid amount.', 'danger')
            return redirect(url_for('wallet'))
        
        if amount <= 0:
            flash('Amount must be a positive number.', 'danger')
            return redirect(url_for('wallet'))

        # For withdrawals, check that user has enough funds
        if transaction_type == 'withdraw':
            if amount > balance:
                flash('Insufficient balance for withdrawal.', 'danger')
                return redirect(url_for('wallet'))
            # Store withdrawal as a negative amount
            amount = -amount

        # Insert the transaction
        conn.execute(
            'INSERT INTO wallet_transactions (user_id, amount, transaction_type) VALUES (?, ?, ?)',
            (session['user_id'], amount, transaction_type)
        )
        conn.commit()
        flash('Transaction successful.', 'success')
        conn.close()
        return redirect(url_for('wallet'))
    
    # Fetch transaction history for display (most recent first)
    transactions = conn.execute(
        'SELECT * FROM wallet_transactions WHERE user_id = ? ORDER BY timestamp DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('wallet.html', balance=balance, transactions=transactions)

    #return render_template('wallet.html', username = session['username'])


#betting system base

#create new bet
@app.route('/create_bet', methods = ['GET', 'POST'])
def create_bet():
    if 'user_id' not in session:
        flash('Please log in to create a bet.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        description = request.form.get('description')
        bet_amount = request.form.get('bet_amount')

        try:
            bet_amount = float(bet_amount)
        except:
            flash('Invalid bet amount.', 'danger')
            return redirect(url_for('create_bet'))
        
        if bet_amount <= 0:
            flash('Invalid bet amount.', 'danger')
            return redirect(url_for('create_bet'))
        
        conn = get_db_connection()
        conn.execute("INSERT INTO bets (creator_id, description, bet_amount, status) VALUES (?,?,?, 'open')", 
                     (session['user_id'], description, bet_amount))
        
        conn.commit()
        conn.close()

        flash('Bet created successfully!', 'success')
        return redirect(url_for('bets'))
    
    return render_template('create_bet.html')

#list all open bets (w filtering eventually)
@app.route('/bets')
def bets():
    if 'user_id' not in session:
        flash('Please log in to view bets.', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # List only bets with status 'open'
    open_bets = conn.execute("SELECT * FROM bets WHERE status = 'open'").fetchall()
    conn.close()
    return render_template('bets.html', bets=open_bets)


# Route to accept a bet
@app.route('/bet/<int:bet_id>/accept', methods=['POST'])
def accept_bet(bet_id):
    if 'user_id' not in session:
        flash('Please log in to accept a bet.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
    bet = conn.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()

    if bet['status'] != 'open':
        flash('This bet is not open for acceptance.', 'danger')
        conn.close()
        return redirect(url_for('bets'))

    # Prevent users from accepting their own bet
    if bet['creator_id'] == session['user_id']:
        flash("You cannot accept your own bet.", 'danger')
        conn.close()
        return redirect(url_for('bets'))

    conn.execute(
        "UPDATE bets SET opponent_id = ?, accepted_at = CURRENT_TIMESTAMP, status = 'accepted' WHERE id = ?",
        (session['user_id'], bet_id)
    )
    conn.commit()
    conn.close()

    flash('Bet accepted successfully.', 'success')
    return redirect(url_for('bets'))


# Resolve a bet (for example, by the bet creator)
@app.route('/bet/<int:bet_id>/resolve', methods=['POST'])
def resolve_bet(bet_id):
    if 'user_id' not in session:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
    bet = conn.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()

    if bet['status'] != 'accepted':
        flash('Bet is not in an accepted state.', 'danger')
        conn.close()
        return redirect(url_for('bets'))

    # Here, only the bet creator is allowed to resolve the bet.
    if bet['creator_id'] != session['user_id']:
        flash('Only the bet creator can resolve the bet.', 'danger')
        conn.close()
        return redirect(url_for('bets'))

    # The form should send a 'winner_id' parameter indicating who won the bet.
    winner_id = request.form.get('winner_id')
    try:
        winner_id = int(winner_id)
    except (ValueError, TypeError):
        flash('Invalid winner id.', 'danger')
        conn.close()
        return redirect(url_for('bets'))

    # Update bet row with resolution details
    conn.execute(
        "UPDATE bets SET winner_id = ?, resolved_at = CURRENT_TIMESTAMP, status = 'completed' WHERE id = ?",
        (winner_id, bet_id)
    )
    conn.commit()
    conn.close()

    flash('Bet resolved successfully.', 'success')
    return redirect(url_for('bets'))




"""
#logout route 
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'sucess')
    return redirect(url_for('index'))
"""

if __name__ == '__main__':
    app.run(debug=True, port = 8080)


    





