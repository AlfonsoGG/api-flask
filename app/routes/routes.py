from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from models.models import Usuario, Pelicula
from schema.schemas import pelicula_schema, peliculas_schema
from database import db
import bcrypt

blue_print = Blueprint('app', __name__)


# Ruta de inicio
@blue_print.route('/', methods=['GET'])
def index():
    return jsonify(respuesta='Rest API con Python, Flask y Mysql')


@blue_print.route('/auth/registrar', methods=['POST'])
def registrar_usuario():
    try:
        # obtener el usuario
        usuario = request.json.get('usuario')
        # obtener la clave
        clave = request.json.get('clave')

        if not usuario or not clave:
            return jsonify(respuesta='Campos Invalidos')
        # Consultar la Base de datos
        existe_usuario = Usuario.query.filter_by(usuario=usuario).first()

        if existe_usuario:
            return jsonify(respuesta='Usuario ya existe'), 400

        # Encriptamos la clave de usuario
        clave_encriptada = bcrypt.hashpw(
            clave.encode('utf-8'), bcrypt.gensalt())

        # creamos usuario
        nuevo_usuario = Usuario(usuario, clave_encriptada)

        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify(respuesta='Usuario Creado Exitosamente'), 201

    except Exception:
        return jsonify(respuesta='Rest API con Python, Flask y Mysql'), 500

# Ruta para Iniciar Sesion


@blue_print.route('/auth/login', methods=['POST'])
def iniciar_sesion():
    try:
        # obtener el usuario
        usuario = request.json.get('usuario')
        # obtener la clave
        clave = request.json.get('clave')

        if not usuario or not clave:
            return jsonify(respuesta='Campos Invalidos'), 400

        # Consultar la Base de datos
        existe_usuario = Usuario.query.filter_by(usuario=usuario).first()
        if not existe_usuario:
            return jsonify(respuesta='Usuario no encontrado')

        es_clave_valida = bcrypt.checkpw(clave.encode(
            'utf-8'), existe_usuario.clave.encode('utf-8'))

        # validamos las claves

        if es_clave_valida:
            access_token = create_access_token(identity=usuario)
            return jsonify(access_token=access_token), 200
        return jsonify(respuesta='Clave o Usuario incorrestos')

    except Exception:
        return jsonify(respuesta='Error en peticion')


"""Rutas protegidas por JWT"""


# Ruta - Crear pelicula
@blue_print.route('/api/peliculas', methods=['POST'])
@jwt_required()
def crear_pelicula():
    try:
        nombre = request.json['nombre']
        estreno = request.json['estreno']
        director = request.json['director']
        reparto = request.json['reparto']
        genero = request.json['genero']
        sinopsis = request.json['sinopsis']

        nueva_pelicula = Pelicula(
            nombre, estreno, director, reparto, genero, sinopsis)
        db.session.add(nueva_pelicula)
        db.session.commit()

        return jsonify(respuesta='Pelicula almacenada Exitosamente')

    except Exception:
        return jsonify(respuesta='Error en peticion'), 500

# Ruta - obtener pelicula
@blue_print.route('/api/peliculas', methods=['GET'])
@jwt_required()
def obtener_peliculas():
    try:
        peliculas = Pelicula.query.all()
        respuesta = peliculas_schema.dump(peliculas)
        return peliculas_schema.jsonify(respuesta),200

    except Exception:
        return jsonify(respuesta='Error en peticion'), 500

# Ruta - obtener por id
@blue_print.route('/api/peliculas/<int:id>', methods=['GET'])
@jwt_required()
def obtener_pelicula_por_id(id):
    try:
        pelicula = Pelicula.query.get(id)
        return pelicula_schema.jsonify(pelicula),200

    except Exception:
        return jsonify(respuesta='Error en peticion'), 500

