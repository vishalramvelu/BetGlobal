import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from database import db

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///bets.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Enable CORS for cross-origin requests
CORS(app)

# Import models after app creation to avoid circular imports
from models import Bet, User, create_bet, accept_bet, get_bet_by_id, get_user_by_id, get_user_bets
from werkzeug.security import generate_password_hash, check_password_hash

# Authentication helper functions
def login_required(f):
    """Decorator to require login for certain routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_authenticated():
    """Check if user is authenticated"""
    return 'user_id' in session

# Routes
@app.route('/landing')
def landing():
    """Landing page for unauthenticated users"""
    return render_template('landing.html')

@app.route('/start-betting')
def start_betting():
    """Start betting - redirects to login if not authenticated"""
    if check_authenticated():
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password are required'})
        
        # Find user by username
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return jsonify({'success': True, 'redirect': url_for('index')})
        else:
            return jsonify({'success': False, 'error': 'Invalid username or password'})
    
    # If already logged in, redirect to main app
    if check_authenticated():
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page and user registration"""
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
        else:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
        
        # Validation
        if not username or not email or not password:
            return jsonify({'success': False, 'error': 'All fields are required'})
        
        if len(username) < 3 or len(username) > 20:
            return jsonify({'success': False, 'error': 'Username must be 3-20 characters long'})
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters long'})
        
        # Check if username or email already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({'success': False, 'error': 'Username already exists'})
            else:
                return jsonify({'success': False, 'error': 'Email already registered'})
        
        try:
            # Create new user
            user = User()
            user.username = username
            user.email = email
            user.password = generate_password_hash(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Auto-login the user
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome to BetGlobal, {user.username}!', 'success')
            return jsonify({'success': True, 'redirect': url_for('index')})
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating user: {str(e)}")
            return jsonify({'success': False, 'error': 'Failed to create account. Please try again.'})
    
    # If already logged in, redirect to main app
    if check_authenticated():
        return redirect(url_for('index'))
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Logout user and redirect to landing page"""
    username = session.get('username', 'User')
    session.clear()
    flash(f'Goodbye, {username}! You have been logged out.', 'secondary')
    return redirect(url_for('landing'))

@app.route('/')
def root():
    """Root route - show landing if not authenticated, otherwise redirect to bets"""
    if check_authenticated():
        return redirect(url_for('index'))
    return render_template('landing.html')

@app.route('/bets')
@login_required
def index():
    """All Bets page - displays all open bets"""
    try:
        # Get filters from request
        search_query = request.args.get('search', '').lower()
        category_filter = request.args.get('category', '')
        status_filter = request.args.get('status', 'open')
        
        # Build query
        query = Bet.query
        
        # Apply status filter
        if status_filter:
            query = query.filter(Bet.status == status_filter)
        
        # Apply search filter
        if search_query:
            from sqlalchemy import or_
            query = query.filter(
                or_(
                    Bet.title.ilike(f'%{search_query}%'),
                    Bet.description.ilike(f'%{search_query}%')
                )
            )
        
        # Apply category filter
        if category_filter:
            query = query.filter(Bet.category == category_filter)
        
        filtered_bets = query.order_by(Bet.created_at.desc()).all()
        
        # Get unique categories for filter dropdown
        categories = [cat[0] for cat in db.session.query(Bet.category).distinct().all()]
        
        # Get users for display
        users = {user.id: user for user in User.query.all()}
        
        return render_template('index.html', 
                             bets=filtered_bets, 
                             users=users, 
                             categories=categories,
                             current_search=search_query,
                             current_category=category_filter,
                             current_status=status_filter)
    except Exception as e:
        logging.error(f"Error in index route: {str(e)}")
        return render_template('index.html', bets=[], users={}, categories=[], error="Failed to load bets")

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard page"""
    try:
        user_id = session.get('user_id')
        user = get_user_by_id(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('index'))
        
        created_bets, accepted_bets = get_user_bets(user_id)
        
        # Calculate statistics
        total_bets = len(created_bets) + len(accepted_bets)
        active_bets = len([bet for bet in created_bets + accepted_bets if bet.status in ['open', 'accepted']])
        completed_bets = len([bet for bet in created_bets + accepted_bets if bet.status == 'completed'])
        
        return render_template('dashboard.html', 
                             user=user,
                             created_bets=created_bets,
                             accepted_bets=accepted_bets,
                             total_bets=total_bets,
                             active_bets=active_bets,
                             completed_bets=completed_bets)
    except Exception as e:
        logging.error(f"Error in dashboard route: {str(e)}")
        return render_template('dashboard.html', user=None, error="Failed to load dashboard")

@app.route('/wallet')
@login_required
def wallet():
    """User wallet page"""
    try:
        user_id = session.get('user_id')
        user = get_user_by_id(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('index'))
        
        return render_template('wallet.html', user=user)
    except Exception as e:
        logging.error(f"Error in wallet route: {str(e)}")
        return render_template('wallet.html', user=None, error="Failed to load wallet")

@app.route('/api/wallet/deposit', methods=['POST'])
@login_required
def api_deposit():
    """API endpoint to deposit money"""
    try:
        data = request.get_json()
        amount = float(data.get('amount', 0))
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
        
        if amount > 10000:  # Limit deposits
            return jsonify({'success': False, 'error': 'Maximum deposit is $10,000'}), 400
        
        user_id = session.get('user_id')
        user = get_user_by_id(user_id)
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Add to balance
        user.balance = (user.balance or 0) + amount
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Successfully deposited ${amount:.2f}',
            'new_balance': user.balance
        })
        
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid amount'}), 400
    except Exception as e:
        logging.error(f"Error in deposit: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Deposit failed'}), 500

@app.route('/api/wallet/withdraw', methods=['POST'])
@login_required
def api_withdraw():
    """API endpoint to withdraw money"""
    try:
        data = request.get_json()
        amount = float(data.get('amount', 0))
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
        
        user_id = session.get('user_id')
        user = get_user_by_id(user_id)
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        if (user.balance or 0) < amount:
            return jsonify({'success': False, 'error': 'Insufficient balance'}), 400
        
        # Subtract from balance
        user.balance = (user.balance or 0) - amount
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Successfully withdrew ${amount:.2f}',
            'new_balance': user.balance
        })
        
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid amount'}), 400
    except Exception as e:
        logging.error(f"Error in withdraw: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Withdrawal failed'}), 500

@app.route('/create-bet')
@login_required
def create_bet_page():
    """Create bet page"""
    return render_template('create_bet.html')

@app.route('/api/create-bet', methods=['POST'])
@login_required
def api_create_bet():
    """API endpoint to create a new bet"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'description', 'amount', 'odds', 'category']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400
        
        # Validate numeric fields
        try:
            amount = float(data['amount'])
            odds = float(data['odds'])
            if amount <= 0 or odds <= 0:
                return jsonify({'success': False, 'error': 'Amount and odds must be positive numbers'}), 400
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid amount or odds format'}), 400
        
        creator_id = session.get('user_id')
        
        # Check if user has sufficient balance
        user = get_user_by_id(creator_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        if (user.balance or 0) < amount:
            return jsonify({'success': False, 'error': f'Insufficient balance. You need ${amount:.2f} but only have ${user.balance:.2f}'}), 400
        
        bet = create_bet(
            creator_id=creator_id,
            title=data['title'],
            description=data['description'],
            amount=amount,
            odds=odds,
            category=data['category']
        )
        
        return jsonify({'success': True, 'bet_id': bet.id})
        
    except Exception as e:
        logging.error(f"Error creating bet: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to create bet'}), 500

@app.route('/api/accept-bet', methods=['POST'])
@login_required
def api_accept_bet():
    """API endpoint to accept a bet"""
    try:
        data = request.get_json()
        bet_id = data.get('bet_id')
        
        if not bet_id:
            return jsonify({'success': False, 'error': 'Bet ID is required'}), 400
        
        acceptor_id = session.get('user_id')
        
        bet = get_bet_by_id(bet_id)
        if not bet:
            return jsonify({'success': False, 'error': 'Bet not found'}), 404
        
        if bet.status != 'open':
            return jsonify({'success': False, 'error': 'Bet is no longer available'}), 400
        
        if bet.creator_id == acceptor_id:
            return jsonify({'success': False, 'error': 'Cannot accept your own bet'}), 400
        
        # Check if acceptor has sufficient balance
        acceptor = get_user_by_id(acceptor_id)
        if not acceptor:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        if (acceptor.balance or 0) < bet.amount:
            return jsonify({'success': False, 'error': f'Insufficient balance. You need ${bet.amount:.2f} but only have ${acceptor.balance:.2f}'}), 400
        
        success = accept_bet(bet_id, acceptor_id)
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to accept bet'}), 500
            
    except Exception as e:
        logging.error(f"Error accepting bet: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to accept bet'}), 500


@app.route('/set-user/<int:user_id>')
def set_user(user_id):
    """Helper route to switch between users for testing"""
    user = get_user_by_id(user_id)
    if user:
        session['user_id'] = user_id
        flash(f'Switched to user: {user.username}', 'success')
    else:
        flash('User not found', 'error')
    return redirect(request.referrer or url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('base.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('base.html'), 500

# Initialize database and sample data
with app.app_context():
    db.create_all()
    
    # Initialize with some sample users for demonstration
    try:
        existing_users = User.query.count()
        if existing_users == 0:
            user1 = User()
            user1.username = 'john_doe'
            user1.email = 'john@example.com'
            user1.password = generate_password_hash('password123')
            user1.balance = 100.0
            
            user2 = User()
            user2.username = 'jane_smith'
            user2.email = 'jane@example.com'
            user2.password = generate_password_hash('password123')
            user2.balance = 100.0
            
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
            logging.info("Sample users created with default password: password123")
    except Exception as e:
        logging.error(f"Error initializing users: {e}")
        db.session.rollback()
