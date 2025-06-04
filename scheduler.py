import threading
import time
import logging
from datetime import datetime, timedelta

logger = logging.getLogger('scheduler')

class BetNotificationScheduler:
    """Simple scheduler to check for expiring bets and send notifications"""
    
    def __init__(self, app):
        self.app = app
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the background scheduler"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.thread.start()
            logger.info("Bet notification scheduler started")
    
    def stop(self):
        """Stop the background scheduler"""
        self.running = False
        if self.thread:
            self.thread.join()
        logger.info("Bet notification scheduler stopped")
    
    def _run_scheduler(self):
        """Main scheduler loop - runs every hour"""
        while self.running:
            try:
                with self.app.app_context():
                    self._check_expiring_bets()
                
                # Sleep for 1 hour (3600 seconds)
                # In production, you might want to use a more sophisticated scheduler
                # like Celery or APScheduler
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error in scheduler: {str(e)}")
                time.sleep(60)  # Wait 1 minute before retrying on error
    
    def _check_expiring_bets(self):
        """Check for expiring bets and send notifications"""
        try:
            from notifications import check_expiring_bets
            check_expiring_bets()
        except Exception as e:
            logger.error(f"Error checking expiring bets: {str(e)}")

# Global scheduler instance
scheduler = None

def init_scheduler(app):
    """Initialize the bet notification scheduler"""
    global scheduler
    if scheduler is None:
        scheduler = BetNotificationScheduler(app)
        scheduler.start()
    return scheduler

def shutdown_scheduler():
    """Shutdown the bet notification scheduler"""
    global scheduler
    if scheduler:
        scheduler.stop()
        scheduler = None