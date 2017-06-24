DROP DATABASE if exists catalogs;
CREATE DATABASE catalogs;

\c catalogs;

CREATE TABLE categories(
    id serial primary key not null,
    name text not null
);

CREATE TABLE items(
    id serial primary key not null,
    name text not null,
    description text,
    owner text not null,
    cat_id int references categories(id)
);

INSERT INTO categories (name) VALUES('Soccer');
INSERT INTO categories (name) VALUES('Basketball');
INSERT INTO categories (name) VALUES('Baseball');
INSERT INTO categories (name) VALUES('Frisbee');
INSERT INTO categories (name) VALUES('Snowboarding');
INSERT INTO categories (name) VALUES('Rock Climbing');
INSERT INTO categories (name) VALUES('Football');
INSERT INTO categories (name) VALUES('Skating');
INSERT INTO categories (name) VALUES('Hockey');

INSERT INTO items (name,cat_id,description,owner) VALUES('Stick',9,' A Hockey Stick','alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Googles',5,'alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Snowboard',5,'alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Two shingaurds',1,'alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Shingaurds',1,'alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Frisbee',4,'alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Bat',3,'alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Jersey',1,'alphawaseem@gmail.com');
INSERT INTO items (name,cat_id,owner) VALUES('Soccer Cleats',1,'alphawaseem@gmail.com');

CREATE VIEW items_cat as select items.name as item,categories.name as category from items,categories where items.cat_id = categories.id;
