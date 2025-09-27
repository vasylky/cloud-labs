from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import boto3, json, mysql.connector

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config["JWT_SECRET_KEY"] = "super_secret_key"
jwt = JWTManager(app)

def get_secret():
    client = boto3.client('secretsmanager', region_name="eu-central-1")
    secret = client.get_secret_value(SecretId="airlinedb/credentials")
    return json.loads(secret['SecretString'])

def get_connection():
    creds = get_secret()
    return mysql.connector.connect(
        host=creds["host"],
        user=creds["user"],
        password=creds["password"],
        database=creds["database"]
    )

@app.route('/users', methods=['GET'])
def get_users():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id, username, email FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(users)


@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id, username, email FROM users WHERE user_id=%s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(user if user else {"error": "User not found"})


@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                       (username, email, password))
        conn.commit()
        return jsonify({"message": "User created"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.get_json()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET username=%s, email=%s WHERE user_id=%s",
                       (data['username'], data['email'], user_id))
        conn.commit()
        return jsonify({"message": "User updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
        conn.commit()
        return jsonify({"message": "User deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        cursor.close()
        conn.close()

# =============================
# AUTH
# =============================

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and bcrypt.check_password_hash(user['password_hash'], password):
        token = create_access_token(identity=user['user_id'])
        return jsonify({"token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# =============================
# FLIGHTS
# =============================

@app.route('/flights', methods=['GET'])
def get_flights():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM flights")
    flights = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(flights)


@app.route('/flights', methods=['POST'])
def add_flight():
    data = request.get_json()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO flights (airline_id, flight_number, departure_airport_id, arrival_airport_id,
            departure_time, arrival_time, baggage_allowance)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            data['airline_id'], data['flight_number'], data['departure_airport_id'],
            data['arrival_airport_id'], data['departure_time'], data['arrival_time'],
            data['baggage_allowance']
        ))
        conn.commit()
        return jsonify({"message": "Flight added"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        cursor.close()
        conn.close()

# =============================
# TICKETS
# =============================

@app.route('/tickets', methods=['POST'])
@jwt_required()
def buy_ticket():
    user_id = get_jwt_identity()
    data = request.get_json()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO tickets (flight_id, user_id, purchase_date, price) VALUES (%s, %s, NOW(), %s)",
                       (data['flight_id'], user_id, data['price']))
        conn.commit()
        return jsonify({"message": "Ticket purchased"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/tickets/<int:user_id>', methods=['GET'])
def get_user_tickets(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM tickets WHERE user_id=%s", (user_id,))
    tickets = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(tickets)

# =============================
# PURCHASE HISTORY
# =============================

@app.route('/purchase_history/<int:user_id>', methods=['GET'])
def get_purchase_history(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT ph.history_id, ph.purchase_date, t.ticket_id, t.price, pm.method_name
        FROM purchase_history ph
        JOIN tickets t ON ph.ticket_id = t.ticket_id
        JOIN payment_methods pm ON ph.payment_methods_payment_method_id = pm.payment_method_id
        WHERE ph.user_id=%s
    """, (user_id,))
    history = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(history)

# =============================
# REVIEWS
# =============================

@app.route('/reviews', methods=['POST'])
@jwt_required()
def add_review():
    user_id = get_jwt_identity()
    data = request.get_json()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO flight_reviews (rating, comment, users_user_id, flights_flight_id) VALUES (%s,%s,%s,%s)",
                       (data['rating'], data['comment'], user_id, data['flight_id']))
        conn.commit()
        return jsonify({"message": "Review added"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/reviews/<int:flight_id>', methods=['GET'])
def get_reviews(flight_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM flight_reviews WHERE flights_flight_id=%s", (flight_id,))
    reviews = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(reviews)

# =============================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
