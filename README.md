# Installation

Requirements:

 * Python 3.5 or greater

Installation:

    pip install -r requirements.txt

# Usage

Set up Django project:

    cd src
    ./manage.py migrate

You should now be able to start the server with

    ./manage.py runserver

At the moment there's no signup process, so you'll have to create
a superuser if you want to log in:

   ./manage.py createsuperuser
