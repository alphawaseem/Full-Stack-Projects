'''
This module initializes the database session and defines some helper functions

'''
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item

engine = create_engine('postgresql://vagrant:password@localhost:5432/catalogs')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


#### HELPER FUNCTIONS TO INTERACT WITH DB ####
def get_all_categories():
    return session.query(Category)


def get_category_by_name(name):
    result = session.query(Category).filter(Category.name.ilike(name))
    if result:
        return result.first()
    return None


def get_category_by_id(id):
    result = session.query(Category).filter(Category.id == id)
    if result:
        return result.first()
    return None


def get_all_items():
    return session.query(Item)


def get_items_by_category(category):
    result = session.query(Item).filter(
        Category.name.ilike(category)).filter(Item.cat_id == Category.id)
    if result:
        return result.all()
    return None


def get_item_by_id(id):
    result = session.query(Item).filter(Item.id == id)
    if result:
        return result.first()
    return None


def get_item_by_name(name):
    result = session.query(Item).filter(Item.name.ilike(name))
    if result:
        return result.first()
    return None


def get_item_by_name_and_category(category, item):
    result = session.query(Category, Item).filter(
        Category.name.ilike(category)).filter(Item.name.ilike(item)).all()
    if result:
        return result[0][1]
    return None


def add_item_todb(item):
    session.add(item)
    session.commit()


def delete_item_fromdb(item):
    session.delete(item)
    session.commit()
