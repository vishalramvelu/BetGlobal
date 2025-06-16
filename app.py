import os
import logging
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename

# Load environment variables from .env file
#load_dotenv()

from flask_cors import CORS
from flask_mail import Mail
from flask_migrate import Migrate
from flask_security import Security, SQLAlchemyUserDatastore, auth_required, hash_password
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import timedelta
from database import db
import stripe

#production level
ENV = os.environ.get("FLASK_ENV", "development").lower()  # or use a custom var, e.g. ENVIRONMENT
IS_PROD = ENV == "production"


# Set up logging configuration
if IS_PROD:
    log_level = logging.INFO
else:
    log_level = logging.DEBUG

logging.basicConfig(
    level=log_level,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)

# Create the app
app = Flask(__name__)
app.secret_key = os.getenv("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for = 1, x_proto=1, x_host=1) #changing this to accomdate deployment



# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'dispute_evidence')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_uploaded_file(file):
    """Validate uploaded file for security"""
    if not file or not file.filename:
        return False, "No file selected"
    
    if not allowed_file(file.filename):
        return False, "File type not allowed. Please upload PNG, JPG, PDF, DOC, or TXT files."
    
    # Check file size (already handled by Flask config, but double-check)
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if file_size > MAX_FILE_SIZE: 
        return False, f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB."
    
    if file_size == 0:
        return False, "File is empty"
    
    # Basic file header validation for common image types
    file_header = file.read(10)
    file.seek(0)  # Reset to beginning
    
    # Check for common malicious file patterns
    if b'<script' in file_header.lower() or b'javascript' in file_header.lower():
        return False, "File contains potentially malicious content"
    
    return True, "File is valid"

# Configure the database
#app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///bets.db")

    
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///bets.db")
    
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Stripe API Key
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# Flask-Security-Too configuration
app.config['SECURITY_PASSWORD_SALT'] = os.environ['SECURITY_PASSWORD_SALT']
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha256'

# Email confirmation - disable for development, enable for production

# Development mode - auto-confirm users, no email needed
app.config['SECURITY_CONFIRMABLE'] = False
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_POST_REGISTER_REDIRECT_ENDPOINT'] = 'index'

app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_TRACKABLE'] = True
app.config['SECURITY_PASSWORDLESS'] = False
app.config['SECURITY_CHANGEABLE'] = True
app.config['SECURITY_EMAIL_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@playstakes.com')
app.config['SECURITY_POST_LOGIN_REDIRECT_ENDPOINT'] = 'index'

# Secure session configuration
if IS_PROD:
    app.config['SESSION_COOKIE_SECURE'] = True #make only https
else:
    app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP in development

if IS_PROD:
    app.config['PREFERRED_URL_SCHEME'] = 'https'


app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Mail configuration - Development mode
    # Development mode - suppress actual email sending, log to console
app.config['TESTING'] = True
app.config['MAIL_SUPPRESS_SEND'] = True
    
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@playstakes.com')

# Initialize the app with the extension
db.init_app(app)
migrate = Migrate(app, db)

# Enable CORS for cross-origin requests
CORS(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "100 per hour"]
)
limiter.init_app(app)

# Initialize security headers
csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline' cdn.jsdelivr.net unpkg.com",
    'style-src': "'self' 'unsafe-inline' cdn.jsdelivr.net",
    'font-src': "'self' cdn.jsdelivr.net",
    'img-src': "'self' data: *.stripe.com"
}


if IS_PROD:
    Talisman(
        app,
        force_https=False,
        strict_transport_security=True,
        content_security_policy=csp
    )
else:
    # Development mode - disable HTTPS enforcement
    Talisman(app,
        force_https=False,
        strict_transport_security=False,
        content_security_policy=csp
    )

# Initialize Flask-Mail
mail = Mail(app)

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
from models import Bet, User, Role, DisputeEvidence, create_bet, accept_bet, get_bet_by_id, get_user_by_id, get_user_bets, check_and_expire_bets, is_bet_expired, Transaction, create_transaction, creator_decide_bet, taker_respond_to_decision, admin_resolve_dispute, get_disputed_bets, get_taker_amount, save_dispute_evidence, get_dispute_evidence, generate_reset_code, set_user_reset_code, verify_user_reset_code, clear_reset_code, get_user_by_email
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta, timezone
from flask_mail import Message

# Setup Flask-Security-Too
from forms import ExtendedRegisterForm

class CustomUserDatastore(SQLAlchemyUserDatastore):
    def create_user(self, **kwargs):
        """Override create_user to handle username field"""
        # Set default balance for new users
        kwargs.setdefault('balance', 0.0)
        return super().create_user(**kwargs)

user_datastore = CustomUserDatastore(db, User, Role)
security = Security(app, user_datastore, 
                   register_form=ExtendedRegisterForm,
                   confirm_register_form=ExtendedRegisterForm)

# Authentication helper functions (keeping for admin routes)
def login_required(f):
    """Decorator to require login for certain routes - replaced by Flask-Security auth_required"""
    return auth_required()(f)

def admin_required(f):
    """Decorator to require admin authentication for admin routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_authenticated' not in session:
            return redirect(url_for('admin_login'))
        
        # Check session timeout (30 minutes)
        admin_login_time = session.get('admin_login_time')
        if admin_login_time:
            # Convert to timezone-aware datetime if needed
            if isinstance(admin_login_time, str):
                admin_login_time = datetime.fromisoformat(admin_login_time.replace('Z', '+00:00'))
            elif admin_login_time.tzinfo is None:
                admin_login_time = admin_login_time.replace(tzinfo=timezone.utc)
            
            if datetime.now(timezone.utc) - admin_login_time > timedelta(minutes=30):
                session.pop('admin_authenticated', None)
                session.pop('admin_login_time', None)
                flash('Admin session expired', 'error')
                return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    return decorated_function

def check_authenticated():
    """Check if user is authenticated"""
    from flask_security import current_user
    return current_user.is_authenticated

def send_reset_code_email(user_email, reset_code, username):
    """Send 2FA reset code via email"""
    try:
        msg = Message(
            subject='Password Reset Verification Code - Play Stakes',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user_email]
        )
        
        msg.html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #2c3e50; margin-bottom: 10px;">🔒 Password Reset Verification</h1>
                    <p style="color: #7f8c8d; font-size: 16px;">Play Stakes Security</p>
                </div>
                
                <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px;">
                    <p style="margin: 0; color: #2c3e50; font-size: 16px;">Hello <strong>{username}</strong>,</p>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    You've requested to reset your password. For security, we need to verify your identity with a 6-digit code.
                </p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <div style="background-color: #3498db; color: white; padding: 20px; border-radius: 8px; display: inline-block;">
                        <p style="margin: 0; font-size: 14px; margin-bottom: 10px;">Your verification code is:</p>
                        <h2 style="margin: 0; font-size: 32px; letter-spacing: 8px; font-weight: bold;">{reset_code}</h2>
                    </div>
                </div>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="margin: 0; color: #856404; font-size: 14px;">
                        <strong>⚠️ Important:</strong> This code will expire in <strong>15 minutes</strong> and can only be used once.
                    </p>
                </div>
                
                <p style="color: #34495e; font-size: 14px; line-height: 1.6;">
                    If you didn't request this password reset, please ignore this email or contact support if you have concerns.
                </p>
                
                <hr style="border: none; border-top: 1px solid #ecf0f1; margin: 30px 0;">
                
                <div style="text-align: center;">
                    <p style="color: #95a5a6; font-size: 12px; margin: 0;">
                        Play Stakes Security Team<br>
                        This is an automated message, please do not reply.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.body = f"""
        Password Reset Verification - Play Stakes
        
        Hello {username},
        
        You've requested to reset your password. For security, please use this 6-digit verification code:
        
        {reset_code}
        
        This code will expire in 15 minutes and can only be used once.
        
        If you didn't request this password reset, please ignore this email.
        
        Play Stakes Security Team
        """
        
        if not app.config.get('MAIL_SUPPRESS_SEND', False):
            mail.send(msg)
            logging.info(f"Reset code sent to {user_email}")
        else:
            logging.info(f"Email suppressed (development mode). Reset code for {user_email}: {reset_code}")
        
        return True
    except Exception as e:
        logging.error(f"Failed to send reset code email: {str(e)}")
        return False

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
    return redirect(url_for('security.login'))

# Login, signup, and logout are now handled by Flask-Security-Too
# Available at /login, /register, /logout endpoints

# Forgot Password with 2FA Routes
@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    """Request password reset with 2FA verification"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            flash('Email address is required', 'error')
            return render_template('security/forgot_password.html')
        
        # Find user by email
        user = get_user_by_email(email)
        
        if user:
            # Generate and set reset code
            reset_code = generate_reset_code()
            if set_user_reset_code(user.id, reset_code):
                # Send email with reset code
                if send_reset_code_email(user.email, reset_code, user.username):
                    flash('A verification code has been sent to your email address.', 'info')
                    return redirect(url_for('verify_reset_code', email=email))
                else:
                    flash('Failed to send verification email. Please try again.', 'error')
            else:
                flash('Failed to generate reset code. Please try again.', 'error')
        else:
            # For security, don't reveal if email exists
            flash('If that email address is in our system, a verification code has been sent.', 'info')
            # Still redirect to verification page to prevent email enumeration
            return render_template('security/verify_reset_code.html', email=email, user_not_found=True)
    
    return render_template('security/forgot_password.html')

@app.route('/verify-reset-code', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_reset_code():
    """Verify 2FA reset code and allow password reset"""
    email = request.args.get('email') or request.form.get('email', '').strip().lower()
    
    if not email:
        flash('Email address is required', 'error')
        return redirect(url_for('forgot_password'))
    
    user = get_user_by_email(email)
    
    if request.method == 'POST':
        reset_code = request.form.get('reset_code', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not reset_code:
            flash('Verification code is required', 'error')
            return render_template('security/verify_reset_code.html', email=email)
        
        if not user:
            flash('Invalid verification attempt', 'error')
            return redirect(url_for('forgot_password'))
        
        # Verify the reset code
        is_valid, message = verify_user_reset_code(user.id, reset_code)
        
        if not is_valid:
            flash(message, 'error')
            return render_template('security/verify_reset_code.html', email=email)
        
        # If code is valid and we have password fields, reset the password
        if new_password and confirm_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return render_template('security/verify_reset_code.html', email=email, code_verified=True)
            
            if new_password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('security/verify_reset_code.html', email=email, code_verified=True)
            
            # Update password
            user.password = generate_password_hash(new_password)
            clear_reset_code(user.id)
            db.session.commit()
            
            flash('Password successfully reset! You can now log in with your new password.', 'success')
            return redirect(url_for('security.login'))
        else:
            # Code is valid, show password reset form
            return render_template('security/verify_reset_code.html', email=email, code_verified=True)
    
    return render_template('security/verify_reset_code.html', email=email)

@app.route('/resend-reset-code', methods=['POST'])
@limiter.limit("3 per minute")
def resend_reset_code():
    """Resend reset code to user's email"""
    email = request.form.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'error': 'Email address is required'}), 400
    
    user = get_user_by_email(email)
    
    if user:
        # Generate new reset code
        reset_code = generate_reset_code()
        if set_user_reset_code(user.id, reset_code):
            if send_reset_code_email(user.email, reset_code, user.username):
                return jsonify({'success': True, 'message': 'New verification code sent to your email'})
            else:
                return jsonify({'success': False, 'error': 'Failed to send email'}), 500
        else:
            return jsonify({'success': False, 'error': 'Failed to generate new code'}), 500
    else:
        # For security, don't reveal if email exists but return success
        return jsonify({'success': True, 'message': 'If that email exists, a new code has been sent'})

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
        from flask_security import current_user
        user = current_user
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('index'))
        
        created_bets, accepted_bets = get_user_bets(user.id)
        
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
        from flask_security import current_user
        user = current_user
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('index'))
        
        # Get filter parameters
        filter_period = request.args.get('period', 'all')  # all, week, month, year
        
        # Build transaction query
        from datetime import datetime, timedelta
        query = Transaction.query.filter_by(user_id=user.id)
        
        # Apply time filters
        if filter_period == 'week':
            week_ago = datetime.now(datetime.timezone.utc) - timedelta(days=7)
            query = query.filter(Transaction.created_at >= week_ago)
        elif filter_period == 'month':
            month_ago = datetime.now(datetime.timezone.utc) - timedelta(days=30)
            query = query.filter(Transaction.created_at >= month_ago)
        elif filter_period == 'year':
            year_ago = datetime.now(datetime.timezone.utc) - timedelta(days=365)
            query = query.filter(Transaction.created_at >= year_ago)
        
        # Get transactions ordered by newest first
        transactions = query.order_by(Transaction.created_at.desc()).all()
        
        # Get related bets for transaction context
        bet_ids = [t.bet_id for t in transactions if t.bet_id]
        bets = {bet.id: bet.to_dict() for bet in Bet.query.filter(Bet.id.in_(bet_ids)).all()} if bet_ids else {}
        
        # Check Stripe withdrawal capabilities
        can_withdraw = False
        if user.stripe_account_id:
            try:
                acct = stripe.Account.retrieve(user.stripe_account_id)
                can_withdraw = acct.payouts_enabled and acct.charges_enabled
            except Exception as e:
                logging.error(f"Error checking Stripe account: {str(e)}")
                can_withdraw = False
        
        return render_template('wallet.html', 
                             user=user.to_dict(), 
                             transactions=[t.to_dict() for t in transactions],
                             bets=bets,
                             current_filter=filter_period,
                             can_withdraw=can_withdraw)
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
        from flask_security import current_user
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        amount = float(data.get('amount', 0))
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
        
        if amount > 10000:  # Limit deposits
            return jsonify({'success': False, 'error': 'Maximum deposit is $10,000'}), 400
        
        user = current_user
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Add to balance
        user.balance = (user.balance or 0) + amount
        
        # Record transaction
        create_transaction(
            user_id=user.id,
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
        from flask_security import current_user
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        amount = float(data.get('amount', 0))
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
        
        user = current_user
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        if (user.balance or 0) < amount:
            return jsonify({'success': False, 'error': 'Insufficient balance'}), 400
        
        # Subtract from balance
        user.balance = (user.balance or 0) - amount
        
        # Record transaction
        create_transaction(
            user_id=user.id,
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

# Stripe integration endpoints
@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    """
    Stripe Checkout Session creation.
    Expects the front-end <form> to POST an 'amount' field (in dollars),
    then converts that to cents, creates a Stripe Session, and redirects.
    """
    # 1) Read 'amount' from the submitted form data
    raw_amount = request.form.get("amount", "").strip()
    if raw_amount == "":
        # No amount provided in form
        flash("Please enter a valid amount before checking out.", "error")
        return redirect(url_for("wallet"))

    try:
        # 2) Convert to float and multiply by 100 to get cents
        dollars = float(raw_amount)
        if dollars < 1.0 or dollars > 10_000.0:
            flash("Amount must be between $1.00 and $10,000.00.", "error")
            return redirect(url_for("wallet"))
        
        amount_in_cents = int(dollars * 100)
    except ValueError:
        flash("Invalid amount format. Please enter a numeric value.", "error")
        return redirect(url_for("wallet"))

    try:
        # 3) Create a Stripe Checkout Session
        session_obj = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": "Deposit to BetGlobal Wallet",
                        },
                        "unit_amount": amount_in_cents,
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            # After successful payment, Stripe will redirect here:
            success_url=url_for("success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            # If user cancels on Stripe, they return here:
            cancel_url=url_for("cancelled", _external=True),
        )

        # 4) Redirect the client (303 See Other) to the Stripe-hosted Checkout page
        return redirect(session_obj.url, code=303)

    except Exception as e:
        logging.error(f"Stripe Session Creation Error: {e}")
        flash("Failed to create Stripe Checkout Session. Please try again.", "error")
        return redirect(url_for("wallet"))
    
@app.route("/success")
@login_required
def success():
    """
    Customer lands here after a successful payment.
    You can fetch the session_id from query string and optionally
    use stripe.checkout.Session.retrieve(...) to get more details
    (e.g. the actual amount paid, customer email, etc.).
    """
    from flask_security import current_user
    session_id = request.args.get("session_id", None)
    if not session_id:
        return "Success page: missing session_id", 400

    try:
        # Retrieve the Checkout Session from Stripe 
        stripe_session = stripe.checkout.Session.retrieve(session_id)
        amount_paid = stripe_session.amount_total / 100.0  # in dollars

        # credit the user's wallet in database
        user = current_user
        if user:
            user.balance = (user.balance or 0) + (amount_paid)
            
            # Record transaction
            create_transaction(
                user_id=user.id,
                transaction_type='deposit',
                amount=amount_paid,
                description=f'Stripe deposit: ${amount_paid:.2f}'
            )
            
            db.session.commit()
        
        flash(f'Successful deposit, {user.username}!', 'success')
        return redirect(url_for("wallet"))
    
    except Exception as e:
        logging.error(f"Error retrieving Stripe session: {e}")
        return "Error retrieving payment details", 500

@app.route("/cancelled")
@login_required
def cancelled():
    """Customer lands here if they cancel the Stripe Checkout flow."""
    flash('Payment was canceled - no charge was made', 'error')
    return redirect(url_for('wallet'))

@app.route("/connect/create-account", methods=["POST", "GET"])
@login_required
def create_connected_account():
    """
    1) Creates a Stripe Connect Express account for the user.
    2) Generates an account link so they can enter KYC info & bank details (hosted by Stripe).
    """
    from flask_security import current_user
    user = current_user
    if not user:
        flash('User not found', 'error')
        return redirect(url_for("wallet"))
    
    # 1) Create a new Express account for them if they don't already have one
    if not user.stripe_account_id:
        account = stripe.Account.create(
            type="express",
            country="US",
            email=user.email,
            capabilities={
                "transfers": {"requested": True},
            }
        )
        user.stripe_account_id = account.id
        db.session.commit()
    else:
        account = stripe.Account.retrieve(user.stripe_account_id)

    # 2) Create an Account Link so they can finish connecting (KYC + bank)
    account_link = stripe.AccountLink.create(
        account=account.id,
        refresh_url=url_for("wallet", _external=True),
        return_url=url_for("wallet", _external=True),
        type="account_onboarding",
    )

    # 3) Redirect them to Stripe's hosted onboarding page
    return redirect(account_link.url)

@app.route("/create-payout", methods=["POST"])
@login_required
def create_payout():
    from flask_security import current_user
    user = current_user
    if not user or not user.stripe_account_id:
        return redirect(url_for("wallet"))

    raw_amount = request.form.get("amount", "").strip()
    if raw_amount == "":
        return redirect(url_for("wallet"))

    try:
        dollars = float(raw_amount)
        if dollars < 0.01 or dollars > (user.balance or 0):
            return redirect(url_for("wallet"))
        amount_in_cents = int(dollars * 100)
    except ValueError:
        return redirect(url_for("wallet"))
    
    # Extra check to make sure our stripe account has enough funds
    try:
        platform_balance = stripe.Balance.retrieve()
        
        available_usd = 0
        for bal in platform_balance.available:
            if bal.currency.lower() == "usd":
                available_usd = bal.amount
                break
        
        if available_usd < amount_in_cents:
            flash("Our payout system is temporarily out of funds. Please try again shortly. Sorry for the inconvenience!", "danger")
            return redirect(url_for("wallet"))
    
    except stripe.error.StripeError as e:
        logging.error(f"Stripe Balance Retrieve Error: {e}")
        flash("Unable to verify payout balance. Try again later.", "danger")
        return redirect(url_for("wallet"))

    try:
        # 1) Create a Transfer from platform → connected account
        _transfer = stripe.Transfer.create(
            amount=amount_in_cents,
            currency="usd",
            destination=user.stripe_account_id,  # sends money into their Connect account
            transfer_group=f"user_{user.id}"
        )

        # 2) Deduct the amount from local database
        user.balance = (user.balance or 0) - dollars
        
        # Record transaction
        create_transaction(
            user_id=user.id,
            transaction_type='withdrawal',
            amount=-dollars,  # Negative amount for withdrawal
            description=f'Stripe withdrawal: ${dollars:.2f}'
        )
        
        db.session.commit()

        flash(f'Withdraw successful, {user.username}! You should see it in your account by end of day!', 'success')
        return redirect(url_for("wallet"))
    
    except stripe.error.StripeError as e:
        logging.error(f"Stripe Transfer Error: {e}")
        return redirect(url_for("wallet"))

@app.route('/create-bet')
@login_required
def create_bet_page():
    """Create bet page"""
    return render_template('create_bet.html')


def validate_bet_input(title, description):
    """
    Validate title and description lengths.
    Returns an error message string if invalid, or None if valid.
    """
    # Normalize inputs
    title_str = title.strip() if isinstance(title, str) else ''
    if len(title_str) < 5:
        return "Bet title must be at least 5 characters"
    
    description_str = description.strip() if isinstance(description, str) else ''
    if len(description_str) < 10:
        return "Bet description must be at least 10 characters"
    
    # Passed checks
    return None


@app.route('/api/create-bet', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def api_create_bet():
    """API endpoint to create a new bet"""
    try:
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        # Validate required fields
        required_fields = ['title', 'description', 'amount', 'odds', 'category']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400
            
        error = validate_bet_input(data.get('title', ''), data.get('description', ''))
        if error:
            # For JSON/AJAX:
            return jsonify({'success': False, 'error': error}), 400
        
        # Validate numeric fields
        try:
            amount = float(data['amount'])
            odds = float(data['odds'])
            if amount <= 0 or odds <= 0:
                return jsonify({'success': False, 'error': 'Amount and odds must be positive numbers'}), 400
            if amount > 10000:
                return jsonify({'success': False, 'error':'Amount must be below 10000'}), 400
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid amount or odds format'}), 400
        
        # Handle expire_time if provided
        expire_time = None
        if data.get('expire_time'):
            try:
                from datetime import datetime, timezone, timedelta
                
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
        
        from flask_security import current_user
        creator_id = current_user.id
        
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
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        bet_id = data.get('bet_id')
        
        if not bet_id:
            return jsonify({'success': False, 'error': 'Bet ID is required'}), 400
        
        from flask_security import current_user
        acceptor_id = current_user.id
        
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
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        bet_id = data.get('bet_id')
        decision = data.get('decision')  # 'creator_wins' or 'acceptor_wins'
        
        if not bet_id or not decision:
            return jsonify({'success': False, 'error': 'Bet ID and decision are required'}), 400
        
        if decision not in ['creator_wins', 'acceptor_wins']:
            return jsonify({'success': False, 'error': 'Invalid decision'}), 400
        
        from flask_security import current_user
        user_id = current_user.id
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
    """API endpoint for bet taker to respond to creator's decision with optional evidence"""
    try:
        # Handle both form data (for files) and JSON data
        if request.content_type and 'multipart/form-data' in request.content_type:
            # Form data with files
            bet_id = request.form.get('bet_id')
            response = request.form.get('response')
            dispute_reason = request.form.get('dispute_reason', '')
            evidence_text = request.form.get('evidence_text', '')
        else:
            # JSON data (backward compatibility)
            data = request.get_json()
            bet_id = data.get('bet_id')
            response = data.get('response')
            dispute_reason = data.get('dispute_reason', '')
            evidence_text = data.get('evidence_text', '')
        
        if not bet_id or not response:
            return jsonify({'success': False, 'error': 'Bet ID and response are required'}), 400
        
        if response not in ['accepted', 'disputed']:
            return jsonify({'success': False, 'error': 'Invalid response'}), 400
        
        if response == 'disputed' and not dispute_reason.strip():
            return jsonify({'success': False, 'error': 'Dispute reason is required when disputing'}), 400
        
        from flask_security import current_user
        user_id = current_user.id
        bet = get_bet_by_id(bet_id)
        
        if not bet:
            return jsonify({'success': False, 'error': 'Bet not found'}), 404
        
        if bet.acceptor_id != user_id:
            return jsonify({'success': False, 'error': 'Only the bet taker can respond to the decision'}), 403
        
        # Process the response
        success = taker_respond_to_decision(bet_id, response, dispute_reason)
        
        if success and response == 'disputed':
            # Save evidence if disputing
            evidence_saved = False
            
            # Save text evidence if provided
            if evidence_text.strip():
                save_dispute_evidence(
                    bet_id=bet_id,
                    user_id=user_id,
                    evidence_type='text',
                    text_content=evidence_text.strip()
                )
                evidence_saved = True
            
            # Save file evidence if provided
            if 'evidence_file' in request.files:
                file = request.files['evidence_file']
                if file and file.filename:
                    # Validate file
                    is_valid, validation_message = validate_uploaded_file(file)
                    if not is_valid:
                        return jsonify({'success': False, 'error': validation_message}), 400
                    
                    try:
                        filename = secure_filename(file.filename)
                        # Create unique filename
                        import uuid
                        unique_filename = f"{uuid.uuid4().hex}_{filename}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        
                        # Ensure upload directory exists
                        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                        
                        # Save file
                        file.save(file_path)
                        
                        # Determine evidence type based on file extension
                        file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
                        evidence_type = 'image' if file_ext in ['png', 'jpg', 'jpeg', 'gif'] else 'file'
                        
                        # Save to database
                        save_dispute_evidence(
                            bet_id=bet_id,
                            user_id=user_id,
                            evidence_type=evidence_type,
                            file_name=filename,
                            file_path=unique_filename  # Store relative path
                        )
                        evidence_saved = True
                    except Exception as e:
                        logging.error(f"Error saving file evidence: {str(e)}")
                        return jsonify({'success': False, 'error': 'Failed to save uploaded file'}), 500
            
            message = f'Bet disputed. Admin will review. Bet ID: {bet_id}'
            if evidence_saved:
                message += ' Evidence has been uploaded.'
            
            return jsonify({'success': True, 'message': message})
        elif success:
            return jsonify({'success': True, 'message': 'Decision accepted. Bet has been resolved.'})
        else:
            return jsonify({'success': False, 'error': 'Failed to submit response'}), 500
            
    except Exception as e:
        logging.error(f"Error in taker response: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to submit response'}), 500

@app.route('/uploads/dispute_evidence/<filename>')
@admin_required
def uploaded_file(filename):
    """Serve uploaded dispute evidence files (admin only)"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/admin-resolve', methods=['POST'])
@admin_required
def api_admin_resolve():
    """API endpoint for admin to resolve disputed bets"""
    try:
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
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
@limiter.limit("5 per minute")
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        logging.info("Admin login POST request received")
        password = request.form.get('password')
        admin_password_hash = os.environ.get('ADMIN_PASSWORD_HASH')
        
        logging.info(f"Password provided: {'***' if password else 'None'}")
        logging.info(f"Admin hash exists: {bool(admin_password_hash)}")
        
        if admin_password_hash and check_password_hash(admin_password_hash, password):
            logging.info("Admin authentication successful")
            session['admin_authenticated'] = True
            session['admin_login_time'] = datetime.now(timezone.utc)
            flash('Welcome to admin dashboard!', 'success')
            logging.info("Redirecting to admin dashboard")
            return redirect(url_for('admin_dashboard'))
        else:
            logging.warning("Admin authentication failed")
            flash('Invalid admin password', 'error')
    
    if 'admin_authenticated' in session:
        logging.info("Admin already authenticated, redirecting to dashboard")
        return redirect(url_for('admin_dashboard'))
    
    logging.info("Rendering admin login page")
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
        logging.info("Admin dashboard accessed")
        
        # Simple fallback values in case of database issues
        total_users = 0
        total_bets = 0
        active_bets = 0
        completed_bets = 0
        total_balance = 0
        total_bet_volume = 0
        
        try:
            # Get basic statistics
            total_users = User.query.count()
            logging.info(f"Total users: {total_users}")
            total_bets = Bet.query.count()
            logging.info(f"Total bets: {total_bets}")
            active_bets = Bet.query.filter(Bet.status.in_(['open', 'accepted'])).count()
            completed_bets = Bet.query.filter_by(status='completed').count()
            
            # Calculate total money in system
            total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
            total_bet_volume = db.session.query(db.func.sum(Bet.amount)).scalar() or 0
        except Exception as db_error:
            logging.error(f"Database error in admin dashboard: {str(db_error)}")
            # Continue with fallback values
        
        logging.info("About to render admin_dashboard.html")
        return render_template('admin_dashboard.html',
                             total_users=total_users,
                             total_bets=total_bets,
                             active_bets=active_bets,
                             completed_bets=completed_bets,
                             total_balance=total_balance,
                             total_bet_volume=total_bet_volume)
    except Exception as e:
        logging.error(f"Error in admin dashboard: {str(e)}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        # Try to render with minimal data
        return render_template('admin_dashboard.html', 
                             total_users=0,
                             total_bets=0,
                             active_bets=0,
                             completed_bets=0,
                             total_balance=0,
                             total_bet_volume=0,
                             error="Failed to load admin dashboard")

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
        
        # Get evidence for each disputed bet
        bet_evidence = {}
        for bet in disputed_bets:
            evidence = get_dispute_evidence(bet.id)
            bet_evidence[bet.id] = [ev.to_dict() for ev in evidence]
        
        return render_template('admin_disputes.html', 
                             disputed_bets=[bet.to_dict() for bet in disputed_bets], 
                             users=users,
                             bet_evidence=bet_evidence)
    except Exception as e:
        logging.error(f"Error in admin disputes: {str(e)}")
        return render_template('admin_disputes.html', 
                             disputed_bets=[], 
                             users={}, 
                             bet_evidence={},
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
def not_found_error(_error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    # For admin routes, try to redirect to admin login
    if request.path.startswith('/admin'):
        return redirect(url_for('admin_login'))
    return render_template('base.html'), 404

@app.errorhandler(500)
def internal_error(_error):
    """Handle 500 errors"""
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    # For admin routes, show error and redirect to admin login
    if request.path.startswith('/admin'):
        flash('Admin dashboard error. Please try again.', 'error')
        return redirect(url_for('admin_login'))
    return render_template('base.html'), 500

@app.errorhandler(400)
def bad_request_error(_error):
    """Handle 400 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Bad request'}), 400
    return render_template('base.html'), 400

@app.errorhandler(403)
def forbidden_error(_error):
    """Handle 403 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('base.html'), 403

@app.errorhandler(429)
def ratelimit_handler(_error):
    """Handle rate limit errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
    flash('Too many requests. Please try again later.', 'error')
    return redirect(request.referrer or url_for('index')), 429

# Initialize database and sample data
with app.app_context():
    db.create_all()
    
    # Initialize with some sample users for demonstration
    try:
        existing_users = User.query.count()
        if existing_users == 0:
            # Create users using Flask-Security-Too's user_datastore
            user1 = user_datastore.create_user(
                username='john_doe',
                email='john@example.com',
                password=hash_password('password123'),
                balance=0.0,
                active=True,
                confirmed_at=datetime.now(datetime.timezone.utc)
            )
            
            user2 = user_datastore.create_user(
                username='jane_smith',
                email='jane@example.com',
                password=hash_password('password123'),
                balance=0.0,
                active=True,
                confirmed_at=datetime.now(datetime.timezone.utc)
            )
            
            db.session.commit()
            logging.info("Sample users created with default password: password123")
        else:
            # Add fs_uniquifier to existing users if they don't have it
            users_without_uniquifier = User.query.filter_by(fs_uniquifier=None).all()
            for user in users_without_uniquifier:
                import uuid
                user.fs_uniquifier = str(uuid.uuid4())
            if users_without_uniquifier:
                db.session.commit()
                logging.info(f"Added fs_uniquifier to {len(users_without_uniquifier)} existing users")
    except Exception as e:
        logging.error(f"Error initializing users: {e}")
        db.session.rollback()

# Initialize notification scheduler
from scheduler import init_scheduler
init_scheduler(app)
