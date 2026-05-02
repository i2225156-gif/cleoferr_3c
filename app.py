import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from functools import wraps
from werkzeug.utils import secure_filename   # ← NUEVO
from db import db
from db2 import get_connection

app = Flask(__name__)
app.secret_key = "clave_secreta_cleoferr"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://prueba-cleofer:Cleoferr@mysql-prueba-cleofer.alwaysdata.net/prueba-cleofer_tienda_online"
app.config["SQLALCHEMY_DATABASE_URI"] = ("mysql+pymysql://prueba-cleofer_anthuanett:Cleoferr@mysql-prueba-cleofer.alwaysdata.net/prueba-cleofer_tienda_online")

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_timeout": 30
}

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
UPLOAD_FOLDER      = os.path.join(app.root_path, 'static', 'img')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024   # 5 MB máximo
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def guardar_imagen(file_field):
    archivo = request.files.get(file_field)
    if not archivo or archivo.filename == '':
        return None
    if not allowed_file(archivo.filename):
        flash('Formato no permitido. Usa JPG, PNG, WEBP o GIF.', 'danger')
        return None
    ext          = archivo.filename.rsplit('.', 1)[1].lower()
    nombre_unico = f"{uuid.uuid4().hex}.{ext}"
    archivo.save(os.path.join(UPLOAD_FOLDER, nombre_unico))
    return nombre_unico
db.init_app(app)
bcrypt = Bcrypt(app)


class Producto(db.Model):
    __tablename__ = "producto"
    id_producto  = db.Column(db.Integer, primary_key=True)
    nombre       = db.Column(db.String(100))
    descripcion  = db.Column(db.Text)
    precio       = db.Column(db.Numeric(10, 2))
    stock        = db.Column(db.Integer, default=0)
    id_categoria = db.Column(db.Integer)
    id_marca     = db.Column(db.Integer)
    estado       = db.Column(db.String(10), default='activo')
    imagen       = db.Column(db.String(255))

    def __repr__(self):
        return f"<Producto {self.nombre}>"


# ── Decorators ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "administrador":
            flash("Acceso denegado.", "danger")
            return redirect(url_for("productos"))
        return f(*args, **kwargs)
    return decorated_function

def escritura_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") not in ("administrador", "vendedor"):
            flash("No tienes permisos para realizar esta acción.", "danger")
            return redirect(url_for("productos"))
        return f(*args, **kwargs)
    return decorated_function


# ── Auth ─────────────────────────────────────────────────────
@app.route('/')
def inicio():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        clave  = request.form['clave']
        conn   = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.id_usuario, u.nombres, u.email, u.contrasena, r.nombre AS rol
            FROM usuario u
            INNER JOIN rol r ON u.id_rol = r.id_rol
            WHERE u.email = %s
        """, (correo,))
        usuario = cursor.fetchone()
        conn.close()

        if usuario and bcrypt.check_password_hash(usuario['contrasena'], clave):
            session['usuario_id'] = usuario['id_usuario']
            session['rol']        = usuario['rol']
            session['nombre']     = usuario['nombres']
            return redirect(url_for('productos'))
        return render_template('login.html', error='Credenciales incorrectas')
    return render_template('login.html')


@app.route('/login_cliente', methods=['GET', 'POST'])
def login_cliente():
    if request.method == 'POST':
        correo     = request.form['correo']
        contrasena = request.form['contrasena']
        conn       = get_connection()
        cursor     = conn.cursor(dictionary=True)
        # Busca el cliente por email — la columna nombre puede variar
        cursor.execute("SELECT * FROM cliente WHERE email = %s", (correo,))
        cliente = cursor.fetchone()
        conn.close()

        if cliente:
            # Soporte bcrypt Y MD5 (según cómo esté guardada)
            import hashlib
            hash_md5 = hashlib.md5(contrasena.encode()).hexdigest()
            stored   = cliente.get('contrasena') or cliente.get('password') or ''
            ok = False
            try:
                ok = bcrypt.check_password_hash(stored, contrasena)
            except Exception:
                ok = (stored == hash_md5)

            if ok:
                nombre_cliente = (
                    cliente.get('nombre') or
                    cliente.get('nombres') or
                    cliente.get('name') or
                    cliente.get('email')
                )
                session['usuario_id'] = cliente.get('id_cliente') or cliente.get('id')
                session['rol']        = 'cliente'
                session['nombre']     = nombre_cliente
                return redirect(url_for('catalogo_cliente'))

        return render_template('login_cliente.html', error='Credenciales incorrectas')
    return render_template('login_cliente.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))



@app.route('/productos')
@login_required
def productos():
    if session.get('rol') == 'cliente':
        return redirect(url_for('catalogo_cliente'))

    categoria = request.args.get('categoria')
    marca     = request.args.get('marca')
    conn      = get_connection()
    cursor    = conn.cursor(dictionary=True)

    query = """
        SELECT p.*, c.nombre AS categoria, m.nombre AS marca
        FROM producto p
        LEFT JOIN categoria c ON p.id_categoria = c.id_categoria
        LEFT JOIN marca m ON p.id_marca = m.id_marca
        WHERE 1=1
    """
    params = []
    if categoria:
        query += " AND c.nombre = %s"
        params.append(categoria)
    if marca:
        query += " AND m.nombre = %s"
        params.append(marca)
    query += " ORDER BY p.id_producto"
    cursor.execute(query, params)
    lista = cursor.fetchall()

    cursor.execute("SELECT * FROM categoria")
    categorias = cursor.fetchall()
    cursor.execute("SELECT * FROM marca")
    marcas = cursor.fetchall()
    conn.close()

    return render_template('productos.html', productos=lista, categorias=categorias, marcas=marcas)


@app.route('/productos/nuevo')
@login_required
@escritura_required
def nuevo_producto():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM categoria")
    categorias = cursor.fetchall()
    cursor.execute("SELECT * FROM marca")
    marcas = cursor.fetchall()
    conn.close()
    return render_template('producto_form.html', categorias=categorias, marcas=marcas)


@app.route('/productos/guardar', methods=['POST'])
@login_required
@escritura_required
def guardar_producto():
    nombre_imagen = guardar_imagen('imagen')
    nuevo = Producto(
        nombre       = request.form['nombre'],
        descripcion  = request.form['descripcion'],
        precio       = request.form['precio'],
        stock        = request.form['stock'],
        id_categoria = request.form['id_categoria'],
        id_marca     = request.form['id_marca'],
        estado       = request.form.get('estado', 'activo'),
        imagen       = nombre_imagen
    )
    db.session.add(nuevo)
    db.session.commit()
    flash("Producto creado correctamente.", "success")
    return redirect(url_for('productos'))


@app.route('/productos/editar/<int:id>')
@login_required
@escritura_required
def editar_producto(id):
    producto = db.get_or_404(Producto, id)
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM categoria")
    categorias = cursor.fetchall()
    cursor.execute("SELECT * FROM marca")
    marcas = cursor.fetchall()
    conn.close()
    return render_template('producto_form.html', producto=producto, categorias=categorias, marcas=marcas)


@app.route('/productos/actualizar/<int:id>', methods=['POST'])
@login_required
@escritura_required
def actualizar_producto(id):
    producto             = db.get_or_404(Producto, id)
    nombre_imagen = guardar_imagen('imagen')            # ← NUEVO
    if nombre_imagen and producto.imagen:               # ← NUEVO: borra imagen vieja
        ruta_vieja = os.path.join(UPLOAD_FOLDER, producto.imagen)
        if os.path.exists(ruta_vieja):
            os.remove(ruta_vieja)
    producto.nombre      = request.form['nombre']
    producto.descripcion = request.form['descripcion']
    producto.precio      = request.form['precio']
    producto.stock       = request.form['stock']
    producto.id_categoria = request.form['id_categoria']
    producto.id_marca    = request.form['id_marca']
    producto.estado      = request.form.get('estado', 'activo')
    if nombre_imagen:                                   # ← CAMBIÓ
        producto.imagen = nombre_imagen
    db.session.commit()
    flash("Producto actualizado correctamente.", "success")
    return redirect(url_for('productos'))


@app.route('/productos/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_producto(id):
    producto = db.get_or_404(Producto, id)
    db.session.delete(producto)
    db.session.commit()
    flash("Producto eliminado correctamente.", "success")
    return redirect(url_for('productos'))



@app.route('/catalogo')
def catalogo_cliente():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, c.nombre AS categoria, m.nombre AS marca
        FROM producto p
        LEFT JOIN categoria c ON p.id_categoria = c.id_categoria
        LEFT JOIN marca m ON p.id_marca = m.id_marca
        WHERE p.estado = 'activo'
        ORDER BY p.id_producto
    """)
    lista = cursor.fetchall()
    conn.close()
    return render_template('catalogo.html', productos=lista)


# ── Gestión de Clientes ───────────────────────────────────────
@app.route('/clientes')
@login_required
@escritura_required
def clientes():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SHOW COLUMNS FROM cliente")
    columnas = [c['Field'] for c in cursor.fetchall()]
    cursor.execute("SELECT * FROM cliente ORDER BY id_cliente DESC")
    lista = cursor.fetchall()
    conn.close()
    return render_template('clientes.html', clientes=lista, columnas=columnas)


@app.route('/clientes/nuevo', methods=['GET', 'POST'])
@login_required
@escritura_required
def nuevo_cliente():
    if request.method == 'POST':
        nombre    = request.form['nombre']
        email     = request.form['email']
        telefono  = request.form.get('telefono', '')
        direccion = request.form.get('direccion', '')
        contrasena = request.form.get('contrasena', '123456')
        hash_pw   = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        conn   = get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO cliente (nombre, email, telefono, direccion, contrasena) VALUES (%s,%s,%s,%s,%s)",
                (nombre, email, telefono, direccion, hash_pw)
            )
            conn.commit()
            flash("Cliente registrado correctamente.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error al registrar cliente: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('clientes'))
    return render_template('cliente_form.html')


@app.route('/clientes/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@escritura_required
def editar_cliente(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        nombre    = request.form['nombre']
        email     = request.form['email']
        telefono  = request.form.get('telefono', '')
        direccion = request.form.get('direccion', '')
        try:
            cursor.execute(
                "UPDATE cliente SET nombre=%s, email=%s, telefono=%s, direccion=%s WHERE id_cliente=%s",
                (nombre, email, telefono, direccion, id)
            )
            conn.commit()
            flash("Cliente actualizado correctamente.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('clientes'))

    cursor.execute("SELECT * FROM cliente WHERE id_cliente = %s", (id,))
    cliente = cursor.fetchone()
    conn.close()
    if not cliente:
        flash("Cliente no encontrado.", "danger")
        return redirect(url_for('clientes'))
    return render_template('cliente_form.html', cliente=cliente)


@app.route('/clientes/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_cliente(id):
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM cliente WHERE id_cliente = %s", (id,))
        conn.commit()
        flash("Cliente eliminado.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('clientes'))


# ── Inventario ────────────────────────────────────────────────
@app.route('/inventario')
@login_required
@escritura_required
def inventario():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.*, p.nombre AS producto_nombre, pr.nombre AS proveedor_nombre,
               u.nombres AS usuario_nombre
        FROM inventario_movimiento i
        LEFT JOIN producto p ON i.id_producto = p.id_producto
        LEFT JOIN proveedor pr ON i.id_proveedor = pr.id_proveedor
        LEFT JOIN usuario u ON i.id_usuario = u.id_usuario
        ORDER BY i.fecha DESC
        LIMIT 200
    """)
    movimientos = cursor.fetchall()

    cursor.execute("SELECT * FROM producto WHERE estado='activo' ORDER BY nombre")
    productos = cursor.fetchall()
    cursor.execute("SELECT * FROM proveedor ORDER BY nombre")
    proveedores = cursor.fetchall()
    conn.close()
    return render_template('inventario.html',
                           movimientos=movimientos,
                           productos=productos,
                           proveedores=proveedores)


@app.route('/inventario/registrar', methods=['POST'])
@login_required
@escritura_required
def registrar_movimiento():
    tipo         = request.form['tipo']           # 'entrada' | 'salida'
    id_producto  = request.form['id_producto']
    id_proveedor = request.form.get('id_proveedor') or None
    cantidad     = int(request.form['cantidad'])
    precio_unit  = request.form.get('precio_unitario') or 0
    observacion  = request.form.get('observacion', '')
    id_usuario   = session['usuario_id']

    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Obtener stock actual
    cursor.execute("SELECT stock FROM producto WHERE id_producto=%s", (id_producto,))
    prod = cursor.fetchone()
    if not prod:
        flash("Producto no encontrado.", "danger")
        conn.close()
        return redirect(url_for('inventario'))

    stock_actual = prod['stock']
    if tipo == 'salida' and cantidad > stock_actual:
        flash(f"Stock insuficiente. Disponible: {stock_actual}", "danger")
        conn.close()
        return redirect(url_for('inventario'))

    nuevo_stock = stock_actual + cantidad if tipo == 'entrada' else stock_actual - cantidad

    try:
        cursor.execute("""
            INSERT INTO inventario_movimiento
                (tipo, id_producto, id_proveedor, cantidad, precio_unitario, observacion, id_usuario, stock_resultante)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (tipo, id_producto, id_proveedor, cantidad, precio_unit, observacion, id_usuario, nuevo_stock))

        cursor.execute("UPDATE producto SET stock=%s WHERE id_producto=%s", (nuevo_stock, id_producto))
        conn.commit()
        flash(f"Movimiento de {'entrada' if tipo=='entrada' else 'salida'} registrado. Nuevo stock: {nuevo_stock}", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error al registrar movimiento: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('inventario'))


# ── Proveedores ───────────────────────────────────────────────
@app.route('/proveedores')
@login_required
@escritura_required
def proveedores():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM proveedor ORDER BY nombre")
    lista = cursor.fetchall()
    conn.close()
    return render_template('proveedores.html', proveedores=lista)


@app.route('/proveedores/nuevo', methods=['GET', 'POST'])
@login_required
@escritura_required
def nuevo_proveedor():
    if request.method == 'POST':
        nombre    = request.form['nombre']
        contacto  = request.form.get('contacto', '')
        telefono  = request.form.get('telefono', '')
        email     = request.form.get('email', '')
        direccion = request.form.get('direccion', '')
        conn      = get_connection()
        cursor    = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO proveedor (nombre, contacto, telefono, email, direccion) VALUES (%s,%s,%s,%s,%s)",
                (nombre, contacto, telefono, email, direccion)
            )
            conn.commit()
            flash("Proveedor registrado.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('proveedores'))
    return render_template('proveedor_form.html')


@app.route('/proveedores/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@escritura_required
def editar_proveedor(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        nombre    = request.form['nombre']
        contacto  = request.form.get('contacto', '')
        telefono  = request.form.get('telefono', '')
        email     = request.form.get('email', '')
        direccion = request.form.get('direccion', '')
        try:
            cursor.execute(
                "UPDATE proveedor SET nombre=%s, contacto=%s, telefono=%s, email=%s, direccion=%s WHERE id_proveedor=%s",
                (nombre, contacto, telefono, email, direccion, id)
            )
            conn.commit()
            flash("Proveedor actualizado.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('proveedores'))
    cursor.execute("SELECT * FROM proveedor WHERE id_proveedor=%s", (id,))
    proveedor = cursor.fetchone()
    conn.close()
    return render_template('proveedor_form.html', proveedor=proveedor)


@app.route('/proveedores/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_proveedor(id):
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM proveedor WHERE id_proveedor=%s", (id,))
        conn.commit()
        flash("Proveedor eliminado.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('proveedores'))


# ── Carrito cliente ────────────────────────────────────────────
@app.route('/carrito')
@login_required
def carrito():
    if session.get('rol') != 'cliente':
        return redirect(url_for('productos'))
    return render_template('carrito.html')


@app.route('/carrito/agregar', methods=['POST'])
@login_required
def carrito_agregar():
    data        = request.get_json()
    id_producto = int(data.get('id_producto', 0))
    cantidad    = int(data.get('cantidad', 1))
    carrito     = session.get('carrito', {})
    key         = str(id_producto)
    if key in carrito:
        carrito[key]['cantidad'] += cantidad
    else:
        conn   = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT nombre, precio FROM producto WHERE id_producto=%s", (id_producto,))
        prod = cursor.fetchone()
        conn.close()
        if prod:
            carrito[key] = {
                'id_producto': id_producto,
                'nombre':      prod['nombre'],
                'precio':      float(prod['precio']),
                'cantidad':    cantidad
            }
    session['carrito'] = carrito
    return {'ok': True, 'items': len(carrito)}


@app.route('/carrito/confirmar', methods=['POST'])
@login_required
def carrito_confirmar():
    data  = request.get_json()
    items = data.get('items', [])
    session['carrito']       = {}
    session['ultimo_pedido'] = items
    return {'ok': True}


@app.route('/pago')
def pago():
    if 'usuario_id' not in session or session.get('rol') != 'cliente':
        flash("Debes iniciar sesión para pagar.", "warning")
        return redirect(url_for('login_cliente'))

    carrito = session.get('carrito', [])
    return render_template('pago.html', productos=carrito)


# ── Cambiar clave ─────────────────────────────────────────────
@app.route('/cambiar_clave', methods=['GET', 'POST'])
@login_required
def cambiar_clave():
    if request.method == 'POST':
        nueva     = request.form['nueva']
        confirmar = request.form['confirmar']
        if nueva != confirmar:
            return render_template('cambiar_clave.html', error='Las contraseñas no coinciden')
        nueva_hash = bcrypt.generate_password_hash(nueva).decode('utf-8')
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE usuario SET contrasena = %s WHERE id_usuario = %s",
                       (nueva_hash, session['usuario_id']))
        conn.commit()
        conn.close()
        flash("Contraseña actualizada correctamente.", "success")
        return redirect(url_for('productos'))
    return render_template('cambiar_clave.html')


if __name__ == '__main__':
    app.run(debug=True)
