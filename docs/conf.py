# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import sys

sys.path.insert(0, os.path.abspath(".."))
django_settings = "settings.test"

project = "Kamu"
copyright = "2024, University of Helsinki"
author = "University of Helsinki"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinxcontrib_django",
]
add_function_parentheses = False
autodoc_typehints = "description"
toc_object_entries_show_parents = "hide"

intersphinx_mapping = {
    "python": ("https://docs.python.org/3.10/", None),
    "django": ("https://docs.djangoproject.com/en/dev/", "https://docs.djangoproject.com/en/dev/_objects/"),
}

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinxdoc"
html_theme_options = {"sidebarwidth": "30em"}
html_static_path = ["_static"]
