import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-local-ca-secret')

    # Data roots inside container; bind-mount these paths for persistence
    DATA_ROOT = os.environ.get('DATA_ROOT', '/data')
    CERTS_ROOT = os.path.join(DATA_ROOT, 'certs')

    DB_DIR = os.path.join(DATA_ROOT, 'db')
    os.makedirs(DB_DIR, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DB_DIR, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False