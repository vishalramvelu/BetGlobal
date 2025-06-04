import logging
from flask_mail import Message, Mail
from flask import current_app
from datetime import datetime, timedelta
from models import User, Bet

# Configure logging for notifications
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('notifications')

def send_notification_email(to_email, subject, template_html, template_text, **template_vars):
    """
    Send email notification - currently logs to console for development
    In production, this will send actual emails
    """
    # Development mode - log email content
    logger.info("=" * 60)
    logger.info(f"EMAIL NOTIFICATION")
    logger.info(f"To: {to_email}")
    logger.info(f"Subject: {subject}")
    logger.info("-" * 40)
    logger.info("HTML Content:")
    logger.info(template_html.format(**template_vars))
    logger.info("-" * 40)
    logger.info("Text Content:")
    logger.info(template_text.format(**template_vars))
    logger.info("=" * 60)
    
    # TODO: For production, uncomment the following code:
    # if not current_app.config.get('TESTING'):
    #     mail = Mail(current_app)
    #     msg = Message(
    #         subject=subject,
    #         recipients=[to_email],
    #         html=template_html.format(**template_vars),
    #         body=template_text.format(**template_vars)
    #     )
    #     mail.send(msg)

def notify_bet_taken(bet_id, taker_user_id):
    """Notify bet creator when someone accepts their bet"""
    try:
        bet = Bet.query.get(bet_id)
        creator = User.query.get(bet.creator_id)
        taker = User.query.get(taker_user_id)
        
        if not bet or not creator or not taker:
            logger.error(f"Failed to find bet or users for notification: bet_id={bet_id}")
            return
        
        taker_amount = bet.amount * bet.odds
        
        subject = f"Your bet has been taken! - {bet.title}"
        
        html_template = """
        <h2>Great news! Someone took your bet!</h2>
        <p>Hi {creator_username},</p>
        <p><strong>{taker_username}</strong> has accepted your bet:</p>
        
        <div style="border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px;">
            <h3>{bet_title}</h3>
            <p><strong>Description:</strong> {bet_description}</p>
            <p><strong>Your stake:</strong> ${bet_amount:.2f}</p>
            <p><strong>Their stake:</strong> ${taker_amount:.2f}</p>
            <p><strong>Odds:</strong> {bet_odds}:1</p>
            <p><strong>Category:</strong> {bet_category}</p>
        </div>
        
        <p>The bet is now active! When the outcome is determined, you'll need to report the result.</p>
        <p><a href="{app_url}/bets">View your active bets</a></p>
        
        <p>Good luck!<br>The BetGlobal Team</p>
        """
        
        text_template = """
        Great news! Someone took your bet!
        
        Hi {creator_username},
        
        {taker_username} has accepted your bet:
        
        Bet: {bet_title}
        Description: {bet_description}
        Your stake: ${bet_amount:.2f}
        Their stake: ${taker_amount:.2f}
        Odds: {bet_odds}:1
        Category: {bet_category}
        
        The bet is now active! When the outcome is determined, you'll need to report the result.
        
        Good luck!
        The BetGlobal Team
        """
        
        send_notification_email(
            to_email=creator.email,
            subject=subject,
            template_html=html_template,
            template_text=text_template,
            creator_username=creator.username,
            taker_username=taker.username,
            bet_title=bet.title,
            bet_description=bet.description,
            bet_amount=bet.amount,
            taker_amount=taker_amount,
            bet_odds=bet.odds,
            bet_category=bet.category,
            app_url="https://playstakes.com"  # TODO: Use actual app URL
        )
        
    except Exception as e:
        logger.error(f"Error sending bet taken notification: {str(e)}")

def notify_bet_expiring(bet_id, days_left):
    """Notify bet creator when bet is expiring soon"""
    try:
        bet = Bet.query.get(bet_id)
        creator = User.query.get(bet.creator_id)
        
        if not bet or not creator:
            logger.error(f"Failed to find bet or creator for expiration notification: bet_id={bet_id}")
            return
        
        if days_left == 1:
            urgency = "URGENT - "
            time_text = "tomorrow"
        elif days_left == 3:
            urgency = ""
            time_text = "in 3 days"
        elif days_left == 7:
            urgency = ""
            time_text = "in 1 week"
        else:
            urgency = ""
            time_text = f"in {days_left} days"
        
        subject = f"{urgency}Your bet expires {time_text} - {bet.title}"
        
        html_template = """
        <h2>Your bet is expiring soon!</h2>
        <p>Hi {creator_username},</p>
        <p>Your bet will expire <strong>{time_text}</strong> if no one accepts it:</p>
        
        <div style="border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px;">
            <h3>{bet_title}</h3>
            <p><strong>Description:</strong> {bet_description}</p>
            <p><strong>Your stake:</strong> ${bet_amount:.2f}</p>
            <p><strong>Odds:</strong> {bet_odds}:1</p>
            <p><strong>Expires:</strong> {expire_date}</p>
        </div>
        
        <p>If your bet expires, your stake will be automatically refunded to your wallet.</p>
        <p><a href="{app_url}/bets">View all live bets</a></p>
        
        <p>Best regards,<br>The BetGlobal Team</p>
        """
        
        text_template = """
        Your bet is expiring soon!
        
        Hi {creator_username},
        
        Your bet will expire {time_text} if no one accepts it:
        
        Bet: {bet_title}
        Description: {bet_description}
        Your stake: ${bet_amount:.2f}
        Odds: {bet_odds}:1
        Expires: {expire_date}
        
        If your bet expires, your stake will be automatically refunded to your wallet.
        
        Best regards,
        The BetGlobal Team
        """
        
        send_notification_email(
            to_email=creator.email,
            subject=subject,
            template_html=html_template,
            template_text=text_template,
            creator_username=creator.username,
            bet_title=bet.title,
            bet_description=bet.description,
            bet_amount=bet.amount,
            bet_odds=bet.odds,
            time_text=time_text,
            expire_date=bet.expire_time.strftime("%B %d, %Y") if bet.expire_time else "No expiration",
            app_url="https://playstakes.com"  # TODO: Use actual app URL
        )
        
    except Exception as e:
        logger.error(f"Error sending bet expiring notification: {str(e)}")

def notify_bet_decision(bet_id):
    """Notify bet taker when creator makes a decision"""
    try:
        bet = Bet.query.get(bet_id)
        creator = User.query.get(bet.creator_id)
        taker = User.query.get(bet.acceptor_id)
        
        if not bet or not creator or not taker:
            logger.error(f"Failed to find bet or users for decision notification: bet_id={bet_id}")
            return
        
        # Determine who the creator thinks won
        if bet.creator_decision == 'creator_wins':
            decision_text = f"{creator.username} believes they won"
            winner_text = creator.username
        else:
            decision_text = f"{creator.username} believes you won"
            winner_text = "you"
        
        subject = f"Decision made on your bet - {bet.title}"
        
        html_template = """
        <h2>The bet creator has made a decision!</h2>
        <p>Hi {taker_username},</p>
        <p>{decision_text} the bet:</p>
        
        <div style="border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px;">
            <h3>{bet_title}</h3>
            <p><strong>Description:</strong> {bet_description}</p>
            <p><strong>Creator's decision:</strong> {winner_text} won</p>
            <p><strong>Your stake:</strong> ${taker_amount:.2f}</p>
            <p><strong>Creator's stake:</strong> ${bet_amount:.2f}</p>
        </div>
        
        <p><strong>What happens next?</strong></p>
        <p>You can either <strong>accept</strong> this decision or <strong>dispute</strong> it if you disagree.</p>
        <p>If you accept, the bet will be resolved immediately. If you dispute, an admin will review the case.</p>
        
        <p><a href="{app_url}/dashboard">Respond to this decision</a></p>
        
        <p>Best regards,<br>The BetGlobal Team</p>
        """
        
        text_template = """
        The bet creator has made a decision!
        
        Hi {taker_username},
        
        {decision_text} the bet:
        
        Bet: {bet_title}
        Description: {bet_description}
        Creator's decision: {winner_text} won
        Your stake: ${taker_amount:.2f}
        Creator's stake: ${bet_amount:.2f}
        
        What happens next?
        You can either accept this decision or dispute it if you disagree.
        If you accept, the bet will be resolved immediately. If you dispute, an admin will review the case.
        
        Visit your dashboard to respond to this decision.
        
        Best regards,
        The BetGlobal Team
        """
        
        taker_amount = bet.amount * bet.odds
        
        send_notification_email(
            to_email=taker.email,
            subject=subject,
            template_html=html_template,
            template_text=text_template,
            taker_username=taker.username,
            decision_text=decision_text,
            winner_text=winner_text,
            bet_title=bet.title,
            bet_description=bet.description,
            bet_amount=bet.amount,
            taker_amount=taker_amount,
            app_url="https://playstakes.com"  # TODO: Use actual app URL
        )
        
    except Exception as e:
        logger.error(f"Error sending bet decision notification: {str(e)}")

def check_expiring_bets():
    """Check for bets expiring in 7, 3, or 1 days and send notifications"""
    try:
        from datetime import datetime, date, timezone, timedelta
        
        # Get current date in EST
        est_offset = timedelta(hours=-5)
        est_tz = timezone(est_offset)
        today = datetime.now(est_tz).date()
        
        # Check for bets expiring in 1, 3, and 7 days
        for days in [1, 3, 7]:
            target_date = today + timedelta(days=days)
            
            expiring_bets = Bet.query.filter(
                Bet.status == 'open',
                Bet.expire_time == target_date
            ).all()
            
            logger.info(f"Found {len(expiring_bets)} bets expiring in {days} day(s)")
            
            for bet in expiring_bets:
                notify_bet_expiring(bet.id, days)
                
    except Exception as e:
        logger.error(f"Error checking expiring bets: {str(e)}")