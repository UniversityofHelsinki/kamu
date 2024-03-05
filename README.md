# Kamu
University of Helsinki application for managing external people, so. people who are not employees or students.

## Development

### Style guide
* Use black for formatting, cmd: "black ."
* Use flake8 for pep8 checks, cmd: "flake8"
* Use isort for sorting imports, cmd: "isort ."
* Use mypy for typing checks, cmd: "mypy ."

### Running tests
./manage.py test

### Running local server
./manage.py runserver --settings=settings.test

Or copy settings/local_settings_example.py to settings/local_settings.py
and modify as necessary to use production.py settings:

./manage.py runserver
