import os
from app import app  # noqa: F401

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=5001, debug=debug_mode)
