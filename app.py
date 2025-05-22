from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)

# Configuration base de données PostgreSQL (Render)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "postgresql://wov_86f2_user:HgvtrT67LVgNYlIEkhARo93c7vnF6nCt@dpg-d0nnt9adbo4c73ccput0-a.frankfurt-postgres.render.com/wov_86f2")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Clé API (à sécuriser plus tard)
API_KEY = "supersecretkey"

# Modèle utilisateur
class User(db.Model):
    __tablename__ = "users"  # correction ici
    id = db.Column(db.Integer, primary_key=True)
    pseudo = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    expiration_date = db.Column(db.Date, nullable=False)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

# Route pour l'admin : ajouter un utilisateur
@app.route('/add_user', methods=['POST'])
def add_user():
    auth_header = request.headers.get("Authorization")
    if auth_header != "Bearer " + API_KEY:
        return jsonify({"error": "Clé API invalide"}), 401

    data = request.get_json()
    pseudo = data.get("pseudo")
    password = data.get("password")
    expiration_date = data.get("expiration_date")

    if not pseudo or not password or not expiration_date:
        return jsonify({"error": "Champs manquants"}), 400

    try:
        expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d").date()
        hashed_password = generate_password_hash(password)
        user = User(pseudo=pseudo, password_hash=hashed_password, expiration_date=expiration_date)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Utilisateur ajouté avec succès"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route de login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    pseudo = data.get("pseudo")
    password = data.get("password")

    if not pseudo or not password:
        return jsonify({"error": "Champs manquants"}), 400

    user = User.query.filter_by(pseudo=pseudo).first()
    if not user or not user.verify_password(password):
        return jsonify({"error": "Identifiants invalides"}), 401

    if datetime.utcnow().date() > user.expiration_date:
        return jsonify({"error": "Abonnement expiré"}), 403

    return jsonify({"message": "Connexion réussie"})

# Page d'accueil
@app.route('/')
def index():
    return jsonify({"message": "API Flask opérationnelle"}), 200

if __name__ == '__main__':
    app.run(debug=True)
