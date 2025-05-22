from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://wov_86f2_user:HgvtrT67LVgNYlIEkhARo93c7vnF6nCt@dpg-d0nnt9adbo4c73ccput0-a.frankfurt-postgres.render.com/wov_86f2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    pseudo = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(512), nullable=False)  # ⬅️ passe de 120 à 512
    expiration_date = db.Column(db.Date, nullable=False)



# Route de connexion
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    pseudo = data.get('pseudo')
    password = data.get('password')

    user = User.query.filter_by(pseudo=pseudo).first()

    if not user:
        return jsonify({'success': False, 'message': 'Utilisateur inconnu'}), 401

    if not check_password_hash(user.password, password):
        return jsonify({'success': False, 'message': 'Mot de passe incorrect'}), 401

    if datetime.utcnow() > user.expiration_date:
        return jsonify({'success': False, 'message': 'Abonnement expiré'}), 403

    return jsonify({'success': True, 'message': 'Connexion réussie'}), 200

# Route pour ajouter un utilisateur (utilisable manuellement par toi)
@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.get_json()
    pseudo = data['pseudo']
    password = generate_password_hash(data['password'])
    expiration_date = datetime.strptime(data['expiration_date'], '%Y-%m-%d')

    if User.query.filter_by(pseudo=pseudo).first():
        return jsonify({'success': False, 'message': 'Utilisateur déjà existant'}), 400

    new_user = User(pseudo=pseudo, password=password, expiration_date=expiration_date)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Utilisateur ajouté avec succès'}), 201

if __name__ == '__main__':
    app.run()
