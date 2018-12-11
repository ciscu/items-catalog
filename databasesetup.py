from sqlalchemy import Column,Integer,String,ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, UniqueConstraint
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
import psycopg2


Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String, index=True)
    picture = Column(String)
    email = Column(String, unique=True)
    password_hash = Column(String)
    provider = Column(String)

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
            "user name": self.name,
            "email": self.email,
            "password": self.password_hash,
            "Provider": self.provider
        }

class Category(Base):
    __tablename__ = "category"
    # Columns
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))

    # Connect the user table
    user = relationship(User)

    @property
    def serialize(self):
        return {
        'name': self.name,
        }

class Item(Base):
    __tablename__ = "item"
    # Columns
    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False)
    description = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))
    category_id = Column(Integer, ForeignKey('category.id'))

    # Connect the user and category table
    user = relationship(User)
    category = relationship(Category)

    @property
    def serialize(self):
        return {
            "category": self.category.name,
            "name": self.name,
            "description": self.description,
            }

    @property
    def apiMachine(self):
        return {
            "name": self.name
            }

engine = create_engine('postgresql://connection:catalogitems@localhost/catalog')


Base.metadata.create_all(engine)
