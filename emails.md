# Email Notifications Setup Guide

## Current Implementation (Development)

Currently, all email notifications are logged to the console for development purposes. The system includes notifications for:

1. **Bet Taken Notification** - Sent to bet creator when someone accepts their bet
2. **Bet Expiring Notifications** - Sent 7, 3, and 1 days before bet expiration
3. **Bet Decision Notification** - Sent to bet taker when creator makes a decision

## Production Deployment Changes Required

### 1. Enable Actual Email Sending

In `notifications.py`, uncomment and modify the production email code:

```python
def send_notification_email(to_email, subject, template_html, template_text, **template_vars):
    """Send email notification"""
    
    # Remove development logging (optional - keep for audit trail)
    # logger.info("EMAIL NOTIFICATION")...
    
    # Enable production email sending
    if not current_app.config.get('TESTING'):
        mail = Mail(current_app)
        msg = Message(
            subject=subject,
            recipients=[to_email],
            html=template_html.format(**template_vars),
            body=template_text.format(**template_vars)
        )
        mail.send(msg)
```

### 2. Environment Configuration

Set the following environment variables:

```bash
# Enable production mode
export FLASK_ENV=production

# Email server configuration
export MAIL_SERVER=smtp.gmail.com
export MAIL_PORT=587
export MAIL_USE_TLS=true
export MAIL_USERNAME=your-app-email@gmail.com
export MAIL_PASSWORD=your-app-password
export MAIL_DEFAULT_SENDER=noreply@playstakes.com

# Security
export SECURITY_PASSWORD_SALT=your-secure-random-salt
export SESSION_SECRET=your-secure-session-key
```

### 3. Email Template Improvements

Consider creating proper HTML email templates in a separate folder:

```
templates/
  emails/
    bet_taken.html
    bet_taken.txt
    bet_expiring.html
    bet_expiring.txt
    bet_decision.html
    bet_decision.txt
```

### 4. Production Scheduler

Replace the simple threading scheduler with a robust solution:

#### Option A: Celery (Recommended)
```python
# Install: pip install celery redis
from celery import Celery

celery = Celery('betglobal')
celery.config_from_object('celeryconfig')

@celery.task
def check_expiring_bets_task():
    from notifications import check_expiring_bets
    check_expiring_bets()

# Schedule with celery beat
# celery beat -A app.celery --loglevel=info
```

#### Option B: APScheduler
```python
# Install: pip install apscheduler
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(
    func=check_expiring_bets,
    trigger="interval",
    hours=1,
    id='check_expiring_bets'
)
scheduler.start()
```

### 5. Email Provider Setup

#### Gmail Setup:
1. Enable 2-Factor Authentication
2. Generate App Password
3. Use App Password as MAIL_PASSWORD

#### Professional Email Service (Recommended):
- **SendGrid**: Reliable, good free tier
- **Mailgun**: Developer-friendly API
- **Amazon SES**: Cost-effective for high volume

### 6. Email Delivery Monitoring

Add email delivery tracking:

```python
# In notifications.py
import logging

email_logger = logging.getLogger('email_delivery')

def send_notification_email(to_email, subject, template_html, template_text, **template_vars):
    try:
        # Send email code...
        email_logger.info(f"Email sent successfully to {to_email}: {subject}")
    except Exception as e:
        email_logger.error(f"Failed to send email to {to_email}: {str(e)}")
        # Optional: Store failed emails for retry
```

### 7. Email Preferences (Future Enhancement)

Add user email preferences:

```python
# Add to User model
class User(db.Model, UserMixin):
    # ... existing fields ...
    email_bet_taken = db.Column(db.Boolean, default=True)
    email_bet_expiring = db.Column(db.Boolean, default=True)
    email_bet_decisions = db.Column(db.Boolean, default=True)
```

### 8. Rate Limiting

Implement email rate limiting to prevent spam:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)

@limiter.limit("5 per minute")
def send_notification_email(...):
    # Email sending code
```

### 9. Email Templates with Branding

Update templates with proper branding and styling:

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        .email-container { max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }
        .content { padding: 20px; }
        .footer { background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; }
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <h1>BetGlobal</h1>
        </div>
        <div class="content">
            <!-- Email content here -->
        </div>
        <div class="footer">
            <p>&copy; 2025 BetGlobal. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
```

### 10. Testing Email Notifications

Add test endpoints for development:

```python
@app.route('/test-notifications')
def test_notifications():
    if app.config.get('TESTING'):
        # Test all notification types
        notify_bet_taken(test_bet_id, test_user_id)
        notify_bet_expiring(test_bet_id, 1)
        notify_bet_decision(test_bet_id)
        return "Test notifications sent (check logs)"
    return "Not available in production"
```

## Current Notification Types

### 1. Bet Taken Notification
- **Trigger**: When someone accepts a bet
- **Recipient**: Bet creator
- **Content**: Bet details, taker info, next steps

### 2. Bet Expiring Notification
- **Trigger**: 7, 3, and 1 days before expiration
- **Recipient**: Bet creator
- **Content**: Bet details, expiration warning

### 3. Bet Decision Notification
- **Trigger**: When bet creator decides outcome
- **Recipient**: Bet taker
- **Content**: Decision details, response options

## Implementation Status

- ✅ Development logging implemented
- ✅ Notification triggers integrated
- ✅ Basic scheduler implemented
- ⏳ Production email sending (ready to enable)
- ⏳ Professional email templates
- ⏳ Robust scheduling system
- ⏳ Email delivery monitoring
- ⏳ User email preferences