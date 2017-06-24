import sys

from sqlalchemy import Column, ForeignKey, Integer, String

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Category(Base):
    __tablename__ = 'categories'
    name = Column(String(25), nullable=False)
    id = Column(Integer, primary_key=True)

    @property
    def serialize(self):
        return {
            'name' : self.name,
            'id' : self.id
        }


class Item(Base):
    __tablename__ = 'items'
    name = Column(String(25), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    cat_id = Column(Integer, ForeignKey('categories.id'))
    owner = Column(String(36),nullable=False)
    cat = relationship(Category)

    @property
    def serialize(self):
        return {
            'id' : self.id,
            'name': self.name,
            'description' : self.description,
            'cat_id' : self.cat_id
        }

engine = create_engine(
    'postgresql://vagrant:password@localhost:5432/catalogs'
)

Base.metadata.create_all(engine)
