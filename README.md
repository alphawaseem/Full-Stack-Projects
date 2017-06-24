# Catalog Udacity Project

## Intro 
> This project is part of udacity's full-stack nanodegree project. This project makes uses of google oauth2 provider to easily authorize and authenticate the user and allows CRUD operatoins to add,update and delete items to the catalog.

## Prerequisite 
1. Virtual Box
2. Vagrant
3. Python 2
4. OAuth2Client Python Package
5. SQLAlchemy Python Package
6. PostgreSQL

## How to run
1. Clone this repo or download zip
2. Browse to the folder from the terminal
3. run vagrant up
4. run vagrant ssh
5. Virtual Machine's Terminal will be started.
6. Then type cd /vagrant/catalog
7. Make sure you have all the dependencies stated above.If not then install them.
8. Then type python project.py
9. Open the following url http://0.0.0.0:5000/ in your browser.

## JSON Endpoints
1. /catalog/json/
2. /catalog/categories/json/
3. /catalog/#category#/json/
4. /catalog/#category#/items/json/
5. /catalog/#category#/#item#/json/
6. /catalog/category/#id#/json/
7. /catalog/item/#id#/json/
> Replace #...# with desired parameters

Common code for the Relational Databases and Full Stack Fundamentals courses
