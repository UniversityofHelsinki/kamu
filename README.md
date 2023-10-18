# UFO registry
University of Helsinki application for managing external people, so. people who are not employees or students.

## Development

### Style guide
* Use black for formatting, cmd: "black ."
* Use isort for sorting imports, cmd: "isort ."
* Use mypy for typing checks, cmd: "mypy ."

### Running tests
./manage.py test

### Running local server
./manage.py runserver --settings=uforegistry.settings.test

Or copy uforegistry/settings/local_settings_example.py to uforegistry/settings/local_settings.py
and modify as necessary to use production.py settings:

./manage.py runserver


