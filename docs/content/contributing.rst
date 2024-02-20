Contributing
============

Development environment
-----------------------

Check :doc:`installation` for more information on how to setup a development environment.

Code style and linting
----------------------

We use black for code formatting and isort for import sorting. Check pyproject.toml for the configuration.

We use mypy for static type checking.

Run tests with following commands::

    black .
    isort .
    mypy .

Run code tests with the following::

    python manage.py test --settings=tests.settings


Committing code
---------------

Create a Merge Request. Each merge will be reviewed by another developer.

- You should rebase your MR to the latest main branch.
- Small patches can usually be done in a single commit.
- For larger features, it's good to use different commits for each logical part of work.
- Make sure that **each commit** is a logical unit of work and that it **passes all the tests**.
- You can and in most cases you must rewrite history of your branch to make it clean and easy to review.
- Use **git rebase -i** and **git commit --amend** to modify your commits until they pass the review process. **Do
  not** create additional fixup commits.

Documentation
-------------

We use Sphinx for documentation. Update docs/ directory as needed.

To compile the documentation, run the following command::

    pip install -r requirement_docs.txt  # If you haven't installed documentation requirements yet.
    make -C docs html

If you are making changes to database, also update the database graph. There is a script to do that::

    sh update_model_graph.sh
