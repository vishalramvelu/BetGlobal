from flask import render_template, request, jsonify, session, redirect, url_for, flash
from app import app, db
from models import Bet, User, create_bet, accept_bet, get_bet_by_id, get_user_by_id, get_user_bets
import logging

@app.route('/')
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
            query = query.filter(
                db.or_(
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
def dashboard():
    """User dashboard page"""
    try:
        # For MVP, we'll use a default user (user ID 1)
        user_id = session.get('user_id', 1)
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

@app.route('/create-bet')
def create_bet_page():
    """Create bet page"""
    return render_template('create_bet.html')

@app.route('/api/create-bet', methods=['POST'])
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
        
        # For MVP, use default user (user ID 1)
        creator_id = session.get('user_id', 1)
        
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
def api_accept_bet():
    """API endpoint to accept a bet"""
    try:
        data = request.get_json()
        bet_id = data.get('bet_id')
        
        if not bet_id:
            return jsonify({'success': False, 'error': 'Bet ID is required'}), 400
        
        # For MVP, use default user (user ID 2 for accepting bets)
        acceptor_id = session.get('user_id', 2)
        
        bet = get_bet_by_id(bet_id)
        if not bet:
            return jsonify({'success': False, 'error': 'Bet not found'}), 404
        
        if bet.status != 'open':
            return jsonify({'success': False, 'error': 'Bet is no longer available'}), 400
        
        if bet.creator_id == acceptor_id:
            return jsonify({'success': False, 'error': 'Cannot accept your own bet'}), 400
        
        success = accept_bet(bet_id, acceptor_id)
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to accept bet'}), 500
            
    except Exception as e:
        logging.error(f"Error accepting bet: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to accept bet'}), 500

@app.route('/api/bets')
def api_get_bets():
    """API endpoint to get all bets with filtering"""
    try:
        bets = app.config['BETS']
        users = app.config['USERS']
        
        # Apply filters
        search_query = request.args.get('search', '').lower()
        category_filter = request.args.get('category', '')
        status_filter = request.args.get('status', '')
        
        filtered_bets = []
        for bet in bets:
            if status_filter and bet.status != status_filter:
                continue
            if search_query and search_query not in bet.title.lower() and search_query not in bet.description.lower():
                continue
            if category_filter and bet.category != category_filter:
                continue
            
            bet_dict = bet.to_dict()
            # Add creator username
            creator = users.get(bet.creator_id)
            bet_dict['creator_username'] = creator['username'] if creator else 'Unknown'
            
            filtered_bets.append(bet_dict)
        
        return jsonify({'success': True, 'bets': filtered_bets})
        
    except Exception as e:
        logging.error(f"Error getting bets: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load bets'}), 500

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
