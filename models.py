from datetime import datetime
from database import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    stripe_account_id = db.Column(db.String(255), nullable = True)

    balance = db.Column(db.Float, default=100.0)  # Starting balance
    total_profit = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    created_bets = db.relationship('Bet', foreign_keys='Bet.creator_id', backref='creator', lazy='dynamic')
    accepted_bets = db.relationship('Bet', foreign_keys='Bet.acceptor_id', backref='acceptor', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'total_profit': self.total_profit,
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
    status = db.Column(db.String(20), default='open')  # 'open', 'accepted', 'completed', 'cancelled'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    winner = db.Column(db.String(20), nullable=True)  # 'creator' or 'acceptor'
    
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
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'winner': self.winner
        }

def get_bet_by_id(bet_id):
    """Get a bet by its ID"""
    return Bet.query.get(bet_id)

def get_user_by_id(user_id):
    """Get a user by their ID"""
    return User.query.get(user_id)

def create_bet(creator_id, title, description, amount, odds, category):
    """Create a new bet and deduct amount from creator's balance"""
    bet = Bet()
    bet.creator_id = creator_id
    bet.title = title
    bet.description = description
    bet.amount = float(amount)
    bet.odds = float(odds)
    bet.category = category
    bet.status = 'open'
    
    # Deduct amount from creator's balance
    creator = User.query.get(creator_id)
    if creator:
        creator.balance = (creator.balance or 0) - float(amount)
    
    db.session.add(bet)
    db.session.commit()
    
    return bet

def accept_bet(bet_id, acceptor_id):
    """Accept a bet and deduct amount from acceptor's balance"""
    bet = Bet.query.get(bet_id)
    if not bet or bet.status != 'open':
        return False
    
    # Deduct amount from acceptor's balance
    acceptor = User.query.get(acceptor_id)
    if acceptor:
        acceptor.balance = (acceptor.balance or 0) - bet.amount
    
    bet.status = 'accepted'
    bet.acceptor_id = acceptor_id
    
    db.session.commit()
    
    return True

def get_user_bets(user_id):
    """Get all bets for a specific user (created and accepted)"""
    user = User.query.get(user_id)
    if not user:
        return [], []
    
    created_bets = user.created_bets.all()
    accepted_bets = user.accepted_bets.all()
    
    return created_bets, accepted_bets
