from datetime import datetime
from database import db
from flask_security import UserMixin, RoleMixin

# Define models for Flask-Security-Too
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=100.0)  # Starting balance
    total_profit = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Flask-Security-Too fields
    active = db.Column(db.Boolean(), default=True)
    fs_uniquifier = db.Column(db.String(255), unique=True)
    confirmed_at = db.Column(db.DateTime())
    
    # Flask-Security-Too trackable fields
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(db.Integer)
    
    # Relationships
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    created_bets = db.relationship('Bet', foreign_keys='Bet.creator_id', backref='creator', lazy='dynamic')
    accepted_bets = db.relationship('Bet', foreign_keys='Bet.acceptor_id', backref='acceptor', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'balance': self.balance,
            'total_profit': self.total_profit,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # 'deposit', 'withdrawal', 'bet_created', 'bet_accepted', 'bet_refund', 'bet_payout'
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    bet_id = db.Column(db.Integer, db.ForeignKey('bet.id'), nullable=True)  # Reference to bet if applicable
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='transactions', lazy=True)
    bet = db.relationship('Bet', backref='transactions', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'transaction_type': self.transaction_type,
            'amount': self.amount,
            'description': self.description,
            'bet_id': self.bet_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Bet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    acceptor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    odds = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='open')  # 'open', 'accepted', 'awaiting_resolution', 'disputed', 'completed', 'cancelled', 'expired'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expire_time = db.Column(db.Date, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    winner = db.Column(db.String(20), nullable=True)  # 'creator' or 'acceptor'
    creator_decision = db.Column(db.String(20), nullable=True)  # 'creator_wins' or 'acceptor_wins'
    taker_response = db.Column(db.String(20), nullable=True)  # 'accepted' or 'disputed'
    admin_decision = db.Column(db.String(20), nullable=True)  # 'creator_wins', 'acceptor_wins', or 'void'
    dispute_reason = db.Column(db.Text, nullable=True)  # Reason for dispute from bet taker
    
    def to_dict(self):
        return {
            'id': self.id,
            'creator_id': self.creator_id,
            'acceptor_id': self.acceptor_id,
            'title': self.title,
            'description': self.description,
            'amount': self.amount,
            'odds': self.odds,
            'category': self.category,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expire_time': self.expire_time.isoformat() if self.expire_time else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'winner': self.winner,
            'creator_decision': self.creator_decision,
            'taker_response': self.taker_response,
            'admin_decision': self.admin_decision,
            'dispute_reason': self.dispute_reason
        }

def get_bet_by_id(bet_id):
    """Get a bet by its ID"""
    return Bet.query.get(bet_id)

def get_user_by_id(user_id):
    """Get a user by their ID"""
    return User.query.get(user_id)

def create_bet(creator_id, title, description, amount, odds, category, expire_time=None):
    """Create a new bet and deduct amount from creator's balance"""
    bet = Bet()
    bet.creator_id = creator_id
    bet.title = title
    bet.description = description
    bet.amount = float(amount)
    bet.odds = float(odds)
    bet.category = category
    bet.status = 'open'
    bet.expire_time = expire_time
    
    # Deduct amount from creator's balance
    creator = User.query.get(creator_id)
    if creator:
        creator.balance = (creator.balance or 0) - float(amount)
    
    db.session.add(bet)
    db.session.flush()  # Flush to get bet.id
    
    # Record transaction
    create_transaction(
        user_id=creator_id,
        transaction_type='bet_created',
        amount=-float(amount),  # Negative amount for deduction
        description=f'Created bet: {title}',
        bet_id=bet.id
    )
    
    db.session.commit()
    
    return bet

def accept_bet(bet_id, acceptor_id):
    """Accept a bet and deduct amount from acceptor's balance"""
    bet = Bet.query.get(bet_id)
    if not bet or bet.status != 'open':
        return False
    
    # Calculate taker amount based on odds
    taker_amount = bet.amount * bet.odds
    
    # Deduct taker amount from acceptor's balance
    acceptor = User.query.get(acceptor_id)
    if acceptor:
        acceptor.balance = (acceptor.balance or 0) - taker_amount
    
    bet.status = 'accepted'
    bet.acceptor_id = acceptor_id
    
    # Record transaction
    create_transaction(
        user_id=acceptor_id,
        transaction_type='bet_accepted',
        amount=-taker_amount,  # Negative amount for deduction
        description=f'Accepted bet: {bet.title}',
        bet_id=bet.id
    )
    
    db.session.commit()
    
    # Send notification to bet creator
    try:
        from notifications import notify_bet_taken
        notify_bet_taken(bet_id, acceptor_id)
    except Exception as e:
        import logging
        logging.error(f"Failed to send bet taken notification: {str(e)}")
    
    return True

def get_user_bets(user_id):
    """Get all bets for a specific user (created and accepted)"""
    user = User.query.get(user_id)
    if not user:
        return [], []
    
    created_bets = user.created_bets.all()
    accepted_bets = user.accepted_bets.all()
    
    return created_bets, accepted_bets

def create_transaction(user_id, transaction_type, amount, description, bet_id=None):
    """Create a new transaction record"""
    transaction = Transaction()
    transaction.user_id = user_id
    transaction.transaction_type = transaction_type
    transaction.amount = amount
    transaction.description = description
    transaction.bet_id = bet_id
    
    db.session.add(transaction)
    # Note: Don't commit here, let the calling function handle the commit
    
    return transaction

def check_and_expire_bets():
    """Check for expired bets and update their status"""
    from datetime import datetime, date, timezone, timedelta
    
    # Get current date in EST (UTC-5, UTC-4 during DST)
    # For simplicity, we'll use UTC-5 (EST)
    est_offset = timedelta(hours=-5)
    est_tz = timezone(est_offset)
    now_est = datetime.now(est_tz).date()
    
    # Find bets that are open and past their expiration date
    expired_bets = Bet.query.filter(
        Bet.status == 'open',
        Bet.expire_time.isnot(None),
        Bet.expire_time < now_est
    ).all()
    
    for bet in expired_bets:
        bet.status = 'expired'
        # Return the bet amount to the creator
        creator = User.query.get(bet.creator_id)
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
    
    if expired_bets:
        db.session.commit()
    
    return len(expired_bets)

def is_bet_expired(bet):
    """Check if a bet is expired"""
    if not bet.expire_time:
        return False
    from datetime import datetime, timezone, timedelta
    
    # Get current date in EST
    est_offset = timedelta(hours=-5)
    est_tz = timezone(est_offset)
    now_est = datetime.now(est_tz).date()
    return now_est > bet.expire_time

def creator_decide_bet(bet_id, decision):
    """Creator decides the outcome of their bet"""
    bet = Bet.query.get(bet_id)
    if not bet or bet.status != 'accepted':
        return False
    
    bet.creator_decision = decision  # 'creator_wins' or 'acceptor_wins'
    bet.status = 'awaiting_resolution'
    
    db.session.commit()
    
    # Send notification to bet taker
    try:
        from notifications import notify_bet_decision
        notify_bet_decision(bet_id)
    except Exception as e:
        import logging
        logging.error(f"Failed to send bet decision notification: {str(e)}")
    
    return True

def taker_respond_to_decision(bet_id, response, dispute_reason=None):
    """Bet taker responds to creator's decision"""
    bet = Bet.query.get(bet_id)
    if not bet or bet.status != 'awaiting_resolution':
        return False
    
    bet.taker_response = response  # 'accepted' or 'disputed'
    
    if response == 'accepted':
        # Resolve bet automatically
        bet.status = 'completed'
        bet.winner = 'creator' if bet.creator_decision == 'creator_wins' else 'acceptor'
        bet.resolved_at = datetime.utcnow()
        _process_bet_payout(bet)
    elif response == 'disputed':
        bet.status = 'disputed'
        bet.dispute_reason = dispute_reason
    
    db.session.commit()
    return True

def admin_resolve_dispute(bet_id, admin_decision):
    """Admin resolves a disputed bet"""
    bet = Bet.query.get(bet_id)
    if not bet or bet.status != 'disputed':
        return False
    
    bet.admin_decision = admin_decision  # 'creator_wins', 'acceptor_wins', or 'void'
    bet.status = 'completed'
    bet.resolved_at = datetime.utcnow()
    
    if admin_decision == 'creator_wins':
        bet.winner = 'creator'
        _process_bet_payout(bet)
    elif admin_decision == 'acceptor_wins':
        bet.winner = 'acceptor'
        _process_bet_payout(bet)
    elif admin_decision == 'void':
        # Return money to both parties
        _process_bet_void(bet)
    
    db.session.commit()
    return True

def _process_bet_payout(bet):
    """Process bet payout to the winner"""
    creator_amount = bet.amount
    taker_amount = bet.amount * bet.odds
    total_pot = creator_amount + taker_amount
    
    if bet.winner == 'creator':
        winner = User.query.get(bet.creator_id)
        if winner:
            winner.balance = (winner.balance or 0) + total_pot
            winner.total_profit = (winner.total_profit or 0) + taker_amount  # Profit is what they won from the other party
            
            create_transaction(
                user_id=bet.creator_id,
                transaction_type='bet_payout',
                amount=total_pot,
                description=f'Won bet: {bet.title}',
                bet_id=bet.id
            )
    elif bet.winner == 'acceptor':
        winner = User.query.get(bet.acceptor_id)
        if winner:
            winner.balance = (winner.balance or 0) + total_pot
            winner.total_profit = (winner.total_profit or 0) + creator_amount  # Profit is what they won from the other party
            
            create_transaction(
                user_id=bet.acceptor_id,
                transaction_type='bet_payout',
                amount=total_pot,
                description=f'Won bet: {bet.title}',
                bet_id=bet.id
            )

def _process_bet_void(bet):
    """Return bet amounts to both parties when bet is voided"""
    creator_amount = bet.amount
    taker_amount = bet.amount * bet.odds
    
    # Return money to creator
    creator = User.query.get(bet.creator_id)
    if creator:
        creator.balance = (creator.balance or 0) + creator_amount
        create_transaction(
            user_id=bet.creator_id,
            transaction_type='bet_refund',
            amount=creator_amount,
            description=f'Refund for voided bet: {bet.title}',
            bet_id=bet.id
        )
    
    # Return money to acceptor
    acceptor = User.query.get(bet.acceptor_id)
    if acceptor:
        acceptor.balance = (acceptor.balance or 0) + taker_amount
        create_transaction(
            user_id=bet.acceptor_id,
            transaction_type='bet_refund',
            amount=taker_amount,
            description=f'Refund for voided bet: {bet.title}',
            bet_id=bet.id
        )

def get_disputed_bets():
    """Get all bets that are currently disputed"""
    return Bet.query.filter_by(status='disputed').all()

def get_taker_amount(bet):
    """Calculate the amount a bet taker needs to wager"""
    return bet.amount * bet.odds
