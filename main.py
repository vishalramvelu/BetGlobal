import os
from app import app  # noqa: F401

if __name__ == '__main__':
    ENV = os.environ.get("FLASK_ENV", "development").lower()
    IS_PROD = ENV == "production"
    debug_mode = not IS_PROD
    app.run(host='0.0.0.0', port=5001, debug=debug_mode)

    