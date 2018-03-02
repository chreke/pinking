# Installation

Requirements:

 * Python 3.5 or greater

Installation:

    pip install -r requirements.txt

*Please note*: Using a [virtual environment][venv] is optional but
highly recommended!

# Usage

Set up Django project:

    cd src
    ./manage.py migrate

You should now be able to start the server with

    ./manage.py runserver

At the moment there's no signup process, so you'll have to create
a superuser if you want to log in:

   ./manage.py createsuperuser

Now you should be able to log in and create "pins".

[venv]: https://docs.python.org/3/tutorial/venv.html
