# 🎯 Play Stakes - Peer-to-Peer Betting Platform

A secure, modern betting platform that connects users worldwide for peer-to-peer wagering without house edges.

## 🚀 Quick Start

### For Development (Testing Features Locally)
```bash
python3 setup_dev.py    # First time setup
python3 run_dev.py      # Start development server
```
📖 **Full Development Guide**: [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md)

### For Production Deployment
```bash
python3 deployment_checklist.py    # Verify production readiness
```
📖 **Full Deployment Guide**: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

## 📁 Project Structure

```
play-stakes/
├── 📋 QUICK_START_DEV.md       # Quick development setup
├── 📖 DEVELOPMENT_GUIDE.md     # Complete development guide
├── 🚀 DEPLOYMENT_GUIDE.md      # Production deployment guide
├── 🛠️ setup_dev.py            # Development environment setup
├── 🔧 run_dev.py               # Development server runner
├── ✅ deployment_checklist.py  # Production readiness checker
├── 🔧 app.py                   # Main Flask application
├── 📊 models.py                # Database models
├── 🎨 templates/               # HTML templates
├── 🎨 static/                  # CSS, JS, images
└── 📁 instance/                # Database and uploads
```

## ✨ Features

- **Peer-to-Peer Betting** - Direct user-to-user wagering
- **No House Edge** - Fair odds between users
- **Secure Payments** - Stripe integration for deposits/withdrawals
- **Dispute Resolution** - Admin panel for conflict resolution
- **File Upload Evidence** - Image/document support for disputes
- **2FA Security** - Two-factor authentication for password resets
- **Real-time Notifications** - Email alerts for bet activities
- **Mobile Responsive** - Works on all devices

## 🛠️ Technology Stack

- **Backend**: Python Flask
- **Database**: PostgreSQL (production) / SQLite (development)
- **Payments**: Stripe Connect
- **Security**: Flask-Security-Too, CSRF protection, rate limiting
- **Frontend**: Bootstrap 5, Feather Icons
- **Email**: Flask-Mail with HTML templates

## 🔧 Development Workflow

1. **Setup Development Environment**
   ```bash
   python3 setup_dev.py
   ```

2. **Start Development Server**
   ```bash
   python3 run_dev.py
   ```

3. **Access Application**
   - Main app: http://localhost:5000
   - Admin panel: http://localhost:5000/admin (password: admin123)

4. **Make Changes & Test**
   - Files auto-reload on changes
   - Use test Stripe card: 4242424242424242
   - Email codes appear in terminal

5. **Deploy to Production**
   ```bash
   git add .
   git commit -m "Feature description"
   git push origin main
   # Follow deployment guide for production updates
   ```

## 🔒 Security Features

- **Rate Limiting** - Prevents abuse on sensitive endpoints
- **CSRF Protection** - Protects against cross-site request forgery
- **Security Headers** - Comprehensive header security with Talisman
- **Input Validation** - Server-side validation on all inputs
- **2FA Authentication** - Two-factor password recovery
- **File Upload Security** - Validated file uploads with virus scanning
- **Admin Session Management** - Secure admin authentication

## 📧 Communication Features

- **Account Management** - Registration, login, password reset
- **Bet Notifications** - Email alerts for bet activities
- **Dispute Evidence** - File upload for bet disputes
- **Admin Notifications** - System-wide communication tools

## 🎮 User Experience

- **Responsive Design** - Mobile-first responsive interface
- **Real-time Updates** - Dynamic content updates
- **Intuitive Navigation** - Clear user interface design
- **Accessibility** - WCAG compliance features

## 📊 Admin Features

- **User Management** - View and manage user accounts
- **Bet Oversight** - Monitor all betting activities
- **Dispute Resolution** - Handle bet conflicts with evidence review
- **System Statistics** - Comprehensive analytics dashboard
- **Security Monitoring** - Track system security metrics

## 🚀 Getting Started

Choose your path:

- **🛠️ I want to develop/test features**: Start with [QUICK_START_DEV.md](QUICK_START_DEV.md)
- **🚀 I want to deploy to production**: Start with [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **📖 I want the full development guide**: Read [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md)

## 📞 Support

For technical issues or questions:
- Check the troubleshooting sections in the guides
- Review error logs in development mode
- Ensure all environment variables are properly set

---

**Built with ❤️ for fair, peer-to-peer betting**