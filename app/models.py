from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='reader')  # admin | reader

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    tld = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    cert_path = db.Column(db.String(512), nullable=False)
    key_path = db.Column(db.String(512), nullable=False)
    serial = db.Column(db.BigInteger, default=1, nullable=False)
    certificates = db.relationship('Certificate', backref='ca', cascade='all, delete-orphan')

    def next_serial(self):
        self.serial += 1
        return self.serial

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ca_id = db.Column(db.Integer, db.ForeignKey('ca.id', ondelete='CASCADE'), nullable=False)
    common_name = db.Column(db.String(255), nullable=False)
    san = db.Column(db.String(1024), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    cert_path = db.Column(db.String(512), nullable=False)
    key_path = db.Column(db.String(512), nullable=False)