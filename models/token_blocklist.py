from utils.extensions import db
from uuid import uuid4
from datetime import datetime, timezone

def generate_uuid():
    return str(uuid4())

class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String, unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __repr__(self):
        return '<TokenBlocklist %r>' % self.jti

    def save(self):
        db.session.add(self)
        db.session.commit()


