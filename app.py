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

# Custom Jinja2 filter for formatting ISO date strings
@app.template_filter('strftime')
def datetime_filter(date_string, format_string='%Y-%m-%d %H:%M'):
    """Convert ISO date string back to formatted date"""
    if not date_string:
        return 'N/A'
    try:
        # Parse ISO format and apply the requested format
        dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        return dt.strftime(format_string)
    except (ValueError, AttributeError):
        return date_string  # Return original if parsing fails

# Import models after app creation to avoid circular imports
from models import Bet, User, create_bet, accept_bet, get_bet_by_id, get_user_by_id, get_user_bets, check_and_expire_bets, is_bet_expired, Transaction, create_transaction, creator_decide_bet, taker_respond_to_decision, admin_resolve_dispute, get_disputed_bets, get_taker_amount
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

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

def admin_required(f):
    """Decorator to require admin authentication for admin routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_authenticated' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def check_authenticated():
    """Check if user is authenticated"""
    return 'user_id' in session

# Routes
@app.route('/landing')
def landing():
    """Landing page for unauthenticated users"""
    try:
        # Get 3 most recent open bets for display
        live_bets = Bet.query.filter_by(status='open').order_by(Bet.created_at.desc()).limit(3).all()
        
        # Get users for display names
        users = {user.id: user.to_dict() for user in User.query.all()}
        
        return render_template('landing.html', live_bets=[bet.to_dict() for bet in live_bets], users=users)
    except Exception as e:
        logging.error(f"Error loading landing page: {str(e)}")
        return render_template('landing.html', live_bets=[], users={})

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
    return redirect(url_for('landing'))

@app.route('/bets')
@login_required
def index():
    """All Bets page - displays all open bets"""
    try:
        # Check for expired bets first
        check_and_expire_bets()
        
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
        users = {user.id: user.to_dict() for user in User.query.all()}
        
        return render_template('index.html', 
                             bets=[bet.to_dict() for bet in filtered_bets], 
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
        active_bets = len([bet for bet in created_bets + accepted_bets if bet.status in ['open', 'accepted', 'awaiting_resolution', 'disputed']])
        completed_bets = len([bet for bet in created_bets + accepted_bets if bet.status == 'completed'])
        
        return render_template('dashboard.html', 
                             user=user.to_dict(),
                             created_bets=[bet.to_dict() for bet in created_bets],
                             accepted_bets=[bet.to_dict() for bet in accepted_bets],
                             total_bets=total_bets,
                             active_bets=active_bets,
                             completed_bets=completed_bets)
    except Exception as e:
        logging.error(f"Error in dashboard route: {str(e)}")
        return render_template('dashboard.html', 
                             user=None, 
                             created_bets=[], 
                             accepted_bets=[], 
                             total_bets=0,
                             active_bets=0,
                             completed_bets=0,
                             error="Failed to load dashboard")

@app.route('/wallet')
@login_required
def wallet():
    """User wallet page with transaction history"""
    try:
        user_id = session.get('user_id')
        user = get_user_by_id(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('index'))
        
        # Get filter parameters
        filter_period = request.args.get('period', 'all')  # all, week, month, year
        
        # Build transaction query
        from datetime import datetime, timedelta
        query = Transaction.query.filter_by(user_id=user_id)
        
        # Apply time filters
        if filter_period == 'week':
            week_ago = datetime.utcnow() - timedelta(days=7)
            query = query.filter(Transaction.created_at >= week_ago)
        elif filter_period == 'month':
            month_ago = datetime.utcnow() - timedelta(days=30)
            query = query.filter(Transaction.created_at >= month_ago)
        elif filter_period == 'year':
            year_ago = datetime.utcnow() - timedelta(days=365)
            query = query.filter(Transaction.created_at >= year_ago)
        
        # Get transactions ordered by newest first
        transactions = query.order_by(Transaction.created_at.desc()).all()
        
        # Get related bets for transaction context
        bet_ids = [t.bet_id for t in transactions if t.bet_id]
        bets = {bet.id: bet.to_dict() for bet in Bet.query.filter(Bet.id.in_(bet_ids)).all()} if bet_ids else {}
        
        return render_template('wallet.html', 
                             user=user.to_dict(), 
                             transactions=[t.to_dict() for t in transactions],
                             bets=bets,
                             current_filter=filter_period)
    except Exception as e:
        logging.error(f"Error in wallet route: {str(e)}")
        return render_template('wallet.html', 
                             user=None, 
                             transactions=[], 
                             bets={}, 
                             current_filter='all',
                             error="Failed to load wallet")

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
        
        # Record transaction
        create_transaction(
            user_id=user_id,
            transaction_type='deposit',
            amount=amount,
            description=f'Deposit: ${amount:.2f}'
        )
        
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
        
        # Record transaction
        create_transaction(
            user_id=user_id,
            transaction_type='withdrawal',
            amount=-amount,  # Negative amount for withdrawal
            description=f'Withdrawal: ${amount:.2f}'
        )
        
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
        
        # Handle expire_time if provided
        expire_time = None
        if data.get('expire_time'):
            try:
                from datetime import datetime, date, timezone, timedelta
                
                # Parse the date from the input
                expire_date = datetime.fromisoformat(data['expire_time'].replace('Z', '+00:00')).date()
                
                # Get current date in EST
                est_offset = timedelta(hours=-5)
                est_tz = timezone(est_offset)
                today_est = datetime.now(est_tz).date()
                
                if expire_date <= today_est:
                    return jsonify({'success': False, 'error': 'Expiration date must be in the future'}), 400
                
                expire_time = expire_date
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid expiration date format'}), 400
        
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
            category=data['category'],
            expire_time=expire_time
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
        
        # Check if bet is expired
        if is_bet_expired(bet):
            bet.status = 'expired'
            # Return money to creator
            creator = get_user_by_id(bet.creator_id)
            if creator:
                creator.balance = (creator.balance or 0) + bet.amount
                
                # Record refund transaction
                create_transaction(
                    user_id=bet.creator_id,
                    transaction_type='bet_refund',
                    amount=bet.amount,
                    description=f'Refund for expired bet: {bet.title}',
                    bet_id=bet.id
                )
            db.session.commit()
            return jsonify({'success': False, 'error': 'This bet has expired'}), 400
        
        if bet.status != 'open':
            return jsonify({'success': False, 'error': 'Bet is no longer available'}), 400
        
        if bet.creator_id == acceptor_id:
            return jsonify({'success': False, 'error': 'Cannot accept your own bet'}), 400
        
        # Check if acceptor has sufficient balance
        acceptor = get_user_by_id(acceptor_id)
        if not acceptor:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        taker_amount = get_taker_amount(bet)
        if (acceptor.balance or 0) < taker_amount:
            return jsonify({'success': False, 'error': f'Insufficient balance. You need ${taker_amount:.2f} but only have ${acceptor.balance:.2f}'}), 400
        
        success = accept_bet(bet_id, acceptor_id)
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to accept bet'}), 500
            
    except Exception as e:
        logging.error(f"Error accepting bet: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to accept bet'}), 500

@app.route('/api/creator-decide', methods=['POST'])
@login_required
def api_creator_decide():
    """API endpoint for bet creator to decide outcome"""
    try:
        data = request.get_json()
        bet_id = data.get('bet_id')
        decision = data.get('decision')  # 'creator_wins' or 'acceptor_wins'
        
        if not bet_id or not decision:
            return jsonify({'success': False, 'error': 'Bet ID and decision are required'}), 400
        
        if decision not in ['creator_wins', 'acceptor_wins']:
            return jsonify({'success': False, 'error': 'Invalid decision'}), 400
        
        user_id = session.get('user_id')
        bet = get_bet_by_id(bet_id)
        
        if not bet:
            return jsonify({'success': False, 'error': 'Bet not found'}), 404
        
        if bet.creator_id != user_id:
            return jsonify({'success': False, 'error': 'Only the bet creator can decide the outcome'}), 403
        
        success = creator_decide_bet(bet_id, decision)
        
        if success:
            return jsonify({'success': True, 'message': 'Decision submitted. Waiting for bet taker response.'})
        else:
            return jsonify({'success': False, 'error': 'Failed to submit decision'}), 500
            
    except Exception as e:
        logging.error(f"Error in creator decision: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to submit decision'}), 500

@app.route('/api/taker-respond', methods=['POST'])
@login_required
def api_taker_respond():
    """API endpoint for bet taker to respond to creator's decision"""
    try:
        data = request.get_json()
        bet_id = data.get('bet_id')
        response = data.get('response')  # 'accepted' or 'disputed'
        dispute_reason = data.get('dispute_reason', '')
        
        if not bet_id or not response:
            return jsonify({'success': False, 'error': 'Bet ID and response are required'}), 400
        
        if response not in ['accepted', 'disputed']:
            return jsonify({'success': False, 'error': 'Invalid response'}), 400
        
        if response == 'disputed' and not dispute_reason.strip():
            return jsonify({'success': False, 'error': 'Dispute reason is required when disputing'}), 400
        
        user_id = session.get('user_id')
        bet = get_bet_by_id(bet_id)
        
        if not bet:
            return jsonify({'success': False, 'error': 'Bet not found'}), 404
        
        if bet.acceptor_id != user_id:
            return jsonify({'success': False, 'error': 'Only the bet taker can respond to the decision'}), 403
        
        success = taker_respond_to_decision(bet_id, response, dispute_reason)
        
        if success:
            if response == 'accepted':
                return jsonify({'success': True, 'message': 'Decision accepted. Bet has been resolved.'})
            else:
                return jsonify({'success': True, 'message': f'Bet disputed. Admin will review. Bet ID: {bet_id}'})
        else:
            return jsonify({'success': False, 'error': 'Failed to submit response'}), 500
            
    except Exception as e:
        logging.error(f"Error in taker response: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to submit response'}), 500

@app.route('/api/admin-resolve', methods=['POST'])
@admin_required
def api_admin_resolve():
    """API endpoint for admin to resolve disputed bets"""
    try:
        data = request.get_json()
        bet_id = data.get('bet_id')
        admin_decision = data.get('admin_decision')  # 'creator_wins', 'acceptor_wins', or 'void'
        
        if not bet_id or not admin_decision:
            return jsonify({'success': False, 'error': 'Bet ID and admin decision are required'}), 400
        
        if admin_decision not in ['creator_wins', 'acceptor_wins', 'void']:
            return jsonify({'success': False, 'error': 'Invalid admin decision'}), 400
        
        success = admin_resolve_dispute(bet_id, admin_decision)
        
        if success:
            return jsonify({'success': True, 'message': f'Dispute resolved: {admin_decision.replace("_", " ")}'})
        else:
            return jsonify({'success': False, 'error': 'Failed to resolve dispute'}), 500
            
    except Exception as e:
        logging.error(f"Error in admin resolution: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to resolve dispute'}), 500

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        password = request.form.get('password')
        if password == "theothegoat6969":
            session['admin_authenticated'] = True
            flash('Welcome to admin dashboard!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin password', 'error')
    
    if 'admin_authenticated' in session:
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_authenticated', None)
    flash('Logged out from admin panel', 'info')
    return redirect(url_for('landing'))

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard main page"""
    try:
        # Get basic statistics
        total_users = User.query.count()
        total_bets = Bet.query.count()
        active_bets = Bet.query.filter(Bet.status.in_(['open', 'accepted'])).count()
        completed_bets = Bet.query.filter_by(status='completed').count()
        
        # Calculate total money in system
        total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
        total_bet_volume = db.session.query(db.func.sum(Bet.amount)).scalar() or 0
        
        return render_template('admin_dashboard.html',
                             total_users=total_users,
                             total_bets=total_bets,
                             active_bets=active_bets,
                             completed_bets=completed_bets,
                             total_balance=total_balance,
                             total_bet_volume=total_bet_volume)
    except Exception as e:
        logging.error(f"Error in admin dashboard: {str(e)}")
        return render_template('admin_dashboard.html', error="Failed to load admin dashboard")

@app.route('/admin/database')
@admin_required
def admin_database():
    """Admin database viewer"""
    try:
        users = User.query.order_by(User.created_at.desc()).all()
        bets = Bet.query.order_by(Bet.created_at.desc()).all()
        
        return render_template('admin_database.html', users=[user.to_dict() for user in users], bets=[bet.to_dict() for bet in bets])
    except Exception as e:
        logging.error(f"Error in admin database viewer: {str(e)}")
        return render_template('admin_database.html', users=[], bets=[], error="Failed to load database data")

@app.route('/admin/disputes')
@admin_required
def admin_disputes():
    """Admin bet disputes page"""
    try:
        disputed_bets = get_disputed_bets()
        users = {user.id: user.to_dict() for user in User.query.all()}
        
        return render_template('admin_disputes.html', 
                             disputed_bets=[bet.to_dict() for bet in disputed_bets], 
                             users=users)
    except Exception as e:
        logging.error(f"Error in admin disputes: {str(e)}")
        return render_template('admin_disputes.html', 
                             disputed_bets=[], 
                             users={}, 
                             error="Failed to load disputed bets")

@app.route('/contact')
def contact():
    """Contact us page"""
    return render_template('contact.html')

@app.route('/terms')
def terms():
    """Terms of service page"""
    return render_template('terms.html')

@app.route('/admin/statistics')
@admin_required
def admin_statistics():
    """Admin live statistics page"""
    try:
        # User statistics
        total_users = User.query.count()
        users_with_balance = User.query.filter(User.balance > 0).count()
        top_users_by_balance = User.query.order_by(User.balance.desc()).limit(5).all()
        top_users_by_profit = User.query.order_by(User.total_profit.desc()).limit(5).all()
        
        # Bet statistics
        total_bets = Bet.query.count()
        open_bets = Bet.query.filter_by(status='open').count()
        accepted_bets = Bet.query.filter_by(status='accepted').count()
        awaiting_resolution_bets = Bet.query.filter_by(status='awaiting_resolution').count()
        disputed_bets = Bet.query.filter_by(status='disputed').count()
        completed_bets = Bet.query.filter_by(status='completed').count()
        cancelled_bets = Bet.query.filter_by(status='cancelled').count()
        
        # Category breakdown
        category_stats = db.session.query(
            Bet.category, 
            db.func.count(Bet.id),
            db.func.sum(Bet.amount)
        ).group_by(Bet.category).all()
        
        # Recent activity
        recent_bets = Bet.query.order_by(Bet.created_at.desc()).limit(10).all()
        recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
        
        return render_template('admin_statistics.html',
                             total_users=total_users,
                             users_with_balance=users_with_balance,
                             top_users_by_balance=[user.to_dict() for user in top_users_by_balance],
                             top_users_by_profit=[user.to_dict() for user in top_users_by_profit],
                             total_bets=total_bets,
                             open_bets=open_bets,
                             accepted_bets=accepted_bets,
                             awaiting_resolution_bets=awaiting_resolution_bets,
                             disputed_bets=disputed_bets,
                             completed_bets=completed_bets,
                             cancelled_bets=cancelled_bets,
                             category_stats=category_stats,
                             recent_bets=[bet.to_dict() for bet in recent_bets],
                             recent_users=[user.to_dict() for user in recent_users])
    except Exception as e:
        logging.error(f"Error in admin statistics: {str(e)}")
        return render_template('admin_statistics.html', 
                             total_users=0,
                             users_with_balance=0,
                             top_users_by_balance=[],
                             top_users_by_profit=[],
                             total_bets=0,
                             open_bets=0,
                             accepted_bets=0,
                             awaiting_resolution_bets=0,
                             disputed_bets=0,
                             completed_bets=0,
                             cancelled_bets=0,
                             category_stats=[],
                             recent_bets=[],
                             recent_users=[],
                             error="Failed to load statistics")


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
