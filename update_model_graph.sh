echo "Installing requirements..."
pip install -r requirements_graph.txt
echo "Generating structural image from models..."
DJANGO_SETTINGS_MODULE=settings.graph_model ./manage.py graph_models kamu -g -o docs/_static/models.png