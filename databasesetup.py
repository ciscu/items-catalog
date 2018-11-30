from sqlalchemy import Column,Integer,String,ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
    	s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']
    	return user_id

    # api callback for users only for ref
    @property
    def serialize(self):
        return {
            "user id": self.id,
            "user name": self.username,
            "email": self.email,
            "password": self.password_hash
        }

class Category(Base):
    __tablename__ = "category"
    # Columns
    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))

    # Connect the user table
    user = relationship(User)

    @property
    def serialize(self):
        return {
        'id': self.id,
        'name': self.name,
        'user': self.user.username
        }

class Item(Base):
    __tablename__ = "item"
    # Columns
    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    category_id = Column(Integer, ForeignKey('category.id'))

    # Connect the user and category table
    user = relationship(User)
    category = relationship(Category)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            }

engine = create_engine('sqlite:///itemscatalog.db')


Base.metadata.create_all(engine)
