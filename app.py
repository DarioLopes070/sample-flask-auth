from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:amdin123@127.0.0.1:3306/flask-crud"

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
# with app.app_context():
#     db.create_all()

#view login
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username and password:
        user= User.query.filter_by(username=username).first()
        # if user and user.password == password:
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticacao realizada com sucesso"})
    return jsonify({"message": "Credenciais invalidas"}), 400        


@app.route('/logout', methods = ["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})



@app.route('/user', methods = ["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role="user")
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuario cadastrado com sucesso"})   

    return jsonify({"message": "Dados invalidos"}), 400 

# ver usuario por ID
@app.route('/user/<int:id_user>', methods = ["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)
    if user:
        return jsonify({"id": user.id, "username": user.username})
    return jsonify({"message": "Usuario nao encontrado"}), 404

#fazer update
@app.route('/user/<int:id_user>', methods = ["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)
    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message": "Operacao nao permitida"}), 403

    if user:
        user.password = data.get("password")
        db.session.commit() 
        return jsonify({"message": f"Usuario {id_user} atualizado com sucesso"}) 
    return jsonify({"message": "Usuario nao encontrado"}), 404


@app.route('/user/<int:id_user>', methods = ["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)
    if current_user.role != "admin":
        return jsonify({"message": "Operacao nao permitida"}), 403
    if id_user == current_user.id:
        return jsonify({"message": "Nao e possivel deletar o usuario logado"}), 403
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} deletado com sucesso"})
    return jsonify({"message": "Usuario nao encontrado"}), 404

if __name__ == "__main__":
    app.run(debug=True, port=8080)
