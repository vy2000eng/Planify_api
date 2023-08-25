from flask import Flask, jsonify, request
import psycopg2
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from db import connect
import datetime

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "imposter_alphabet"
jwt = JWTManager(app)

from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    get_jwt_identity,
    create_refresh_token,
)


# your API endpoints go here


# this endpoint is for loggin a user in
# ogin() returns an auth token, which the user then can use to access the other endpoints
@app.route("/login", methods=["POST"])
def login():
    user_name = request.json.get("username", None)
    password = request.json.get("password", None)

    if not user_name:
        return jsonify({"error": "username is required"}), 400
    if not password:
        return jsonify({"error": "password is required"}), 400

    conn = connect()
    cur = conn.cursor()
    cur.execute("select * from tasks.users where username=%s", (user_name,))
    user = cur.fetchone()
    # print(user)
    # cur.close()
    # conn.close()

    if user is None:
        return jsonify({"error": "invlaid credentials"}), 401
    if not check_password_hash(user[2], password):
        return jsonify({"error": "invalid credentials"}), 401

    access_token = create_access_token(
        identity=user_name, expires_delta=timedelta(seconds=30)
    )
    refresh_token = create_refresh_token(identity=user_name)
    expiry_date = datetime.datetime.now() + timedelta(minutes=5)
    cur.execute("select * from tasks.refresh_token where user_id = %s", (user_name,))
    existing_entry = cur.fetchone()

    if existing_entry is None:
        cur.execute(
            "insert into tasks.refresh_token (user_id, token, expires_at, is_active) values (%s,%s,%s,%s)",
            (user_name, refresh_token, expiry_date, True),
        )
    else:
        cur.execute(
            "update tasks.refresh_token set  token = %s, expires_at = %s, is_active = %s where user_id = %s",
            (
                refresh_token,
                expiry_date,
                True,
                user_name,
            ),
        )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"acess_token": access_token, "refresh_token": refresh_token}), 200


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    conn = connect()
    cur = conn.cursor()
    cur.execute("select * from tasks.refresh_token where user_id = %s", (current_user,))
    entry = cur.fetchone()
    if entry is None or entry[4] == False or entry[3] < datetime.datetime.now():
        return jsonify({"error": "Refresh token expired "})

    access_token = create_access_token(
        identity=current_user, expires_delta=timedelta(seconds=30)
    )
    refresh_token = create_refresh_token(identity=current_user)
    expiry_date = datetime.datetime.now() + timedelta(minutes=5)
    cur.execute(
        "update tasks.refresh_token set token = %s, expires_at = %s, is_active = %s where user_id = %s",
        (
            refresh_token,
            expiry_date,
            True,
            current_user,
        ),
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"acess_token": access_token, "refresh token": refresh_token}), 200


# this endpoint is for creating a user
# stored in user table
@app.route("/create_user", methods=["POST"])
def create_user():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    # print(request.json)
    # print(request.json.get("email", None))

    # validate input
    if not username:
        return jsonify({"error": "username is required"}), 400
    if not password:
        return jsonify({"error": "password is required"}), 400

    # create new user
    hashed_password = generate_password_hash(password)
    new_user = {
        "username": username,
        "password": hashed_password,
    }
    conn = connect()
    cur = conn.cursor()
    try:
        cur.execute(
            "insert into tasks.users (username,password_hash)" + "values(%s,%s)",
            (new_user["username"], new_user["password"]),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "user created successfully"}), 201
    except (Exception, psycopg2.DatabaseError) as e:
        return jsonify({"error": str(e)}), 500


# this endpoint is for getting the tasks which are specifc to the user via jwt_required
@app.route("/tasks")
@jwt_required()
def get_tasks():
    current_user = get_jwt_identity()
    # print(current_user)
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "select * from tasks.task_table where user_id= %s",
        (current_user,),
    )

    result = cur.fetchall()
    # print(result)
    tasks = []

    for row in result:
        task = {
            "id": row[0],
            "name": row[1],
            "task_name": row[2],
            "task_description": row[3],
            "priority": row[4],
            "created_at": row[5],
            "completed": row[7],
            "due_date": row[8],
        }
        # print(task)
        tasks.append(task)
    cur.close()
    conn.close()

    return jsonify(tasks)


@app.route("/completed_tasks", methods=["GET"])
@jwt_required()
def get_completed_tasks():
    current_user = get_jwt_identity()
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "select * from tasks.task_table where user_id = %s and completed = true",
        (current_user,),
    )
    result = cur.fetchall()

    tasks = []

    for row in result:
        task = {
            "id": row[0],
            "name": row[1],
            "task_name": row[2],
            "task_description": row[3],
            "priority": row[4],
            "created_at": row[5],
            "completed": row[7],
            "due_date": row[8],
        }
        # print(task)
        tasks.append(task)
    cur.close()
    conn.close()

    return jsonify(tasks)


# this endpoint is for creating a task for a specific user, via jwt_required()
@app.route("/create_task", methods=["POST"])
@jwt_required()
def create_task():
    current_user = get_jwt_identity()
    title = request.json["title"]
    description = request.json.get("description", "")
    priority = request.json.get("priority", 1)
    due_date = request.json.get("due_date")
    print(due_date)

    try:
        conn = connect()
        cur = conn.cursor()
        cur.execute(
            "insert into tasks.task_table (user_id, title, description, priority, due_date)"
            + "values (%s, %s,%s,%s,%s)",
            (current_user, title, description, priority, due_date),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Task created succesfully."}), 201
    except (Exception, psycopg2.DatabaseError) as e:
        return jsonify({"error": str(e)}), 500


# TO SELF:
# this endpoint is getting a specific user task
# the way u get the current user is through the get_jwt_identity, even though, it isnt passed anywhere
# that is why this route requires the jwt
# the way this api is structured is, the specifc user tasks will be loaded in, and through that you will be able to get the id
# this is because even though u dont necesarilly have to show all the information loaded in, ull have access to the specific id of a task
# this id is the primary key of the tasks table, and the tasks table has a foriegn key constraint on the user_id column from the users table
@app.route("/tasks/<int:task_id>", methods=["GET"])
@jwt_required
def get_task(task_id):
    try:
        conn = connect()
        cur = conn.cursor()
        current_user = get_jwt_identity()
        cur.execute(
            "select * from tasks.task_table where id = %s and user_id = %s",
            (task_id, current_user),
        )
        task = cur.fetchone()
        if task is None:
            return (jsonify({"message": "Task is not found"}),)
        else:
            return (
                jsonify(
                    {
                        "id": task[0],
                        "user_id": task[1],
                        "title": task[2],
                        "description": task[3],
                        "priority": task[4],
                        "due_date": task[5],
                    }
                ),
                200,
            )
    except (Exception, psycopg2.DatabaseError) as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/update_is_true/<int:task_id>", methods=["PUT"])
@jwt_required()
def update_is_true(task_id):
    current_user = get_jwt_identity()
    isTrue = request.json["isTrue"]
    try:
        conn = connect()
        cur = conn.cursor()
        cur.execute(
            "update tasks.task_table set completed = %s where id= %s and user_id= %s",
            (isTrue, task_id, current_user),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Task updated succesfully."})
    except (Exception, psycopg2.DatabaseError) as e:
        return jsonify({"error": str(e)}), 500


# you don't necessarily need the authentication, because youll be able to update a task just based on the id, this is just a security measure
# so that unauthorized users dont have access to this.
@app.route("/update_task/<int:task_id>", methods=["PUT"])
@jwt_required()
def update_task(task_id):
    title = request.json["title"]
    description = request.json.get("description", "")
    priority = request.json.get("priority", 1)
    due_date = request.json.get("due_date")

    current_user = get_jwt_identity()
    try:
        conn = connect()
        cur = conn.cursor()
        cur.execute(
            "update tasks.task_table set title = %s, description = %s,priority = %s, updated_at = now(), due_date = %s where id = %s and user_id = %s",
            (title, description, priority, due_date, task_id, current_user),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Task updated succesfully."}), 200
    except (Exception, psycopg2.DatabaseError) as e:
        return jsonify({"error": str(e)}), 500


@app.route("/delete/<int:task_id>", methods=["DELETE"])
@jwt_required()
def delete_task(task_id):
    try:
        conn = connect()
        cur = conn.cursor()
        current_user = get_jwt_identity()
        cur.execute(
            "delete from tasks.task_table where id = %s and user_id = %s",
            (task_id, current_user),
        )
        conn.commit()
        cur.close()
        conn.close()
        return (jsonify({"message": "Task deleted succesfully"}), 200)
    except (Exception, psycopg2.DatabaseError) as e:
        return jsonify({"Error": str(e)}), 500


@app.route("/get_number_of_tasks", methods=["GET"])
@jwt_required()
def get_number_of_tasks():
    try:
        conn = connect()
        cur = conn.cursor()
        current_user = get_jwt_identity()
        cur.execute(
            "select count(*) from tasks.task_table where user_id = %s",
            (current_user,),
        )
        task_num = cur.fetchone()[0]
        cur.close()
        conn.close()
        return jsonify({"number_of_tasks": str(task_num)}), 200
    except (Exception, psycopg2.DatabaseError) as e:
        return jsonify({"Error": str(e)}), 500


@app.route("/get_tasks_in_acsending")
@jwt_required()
def tasks_in_ascending_order():
    conn = connect()
    cur = conn.cursor()
    current_user = get_jwt_identity()
    # select * from tasks.task_table where user_id= 'user_1' order by id
    cur.execute(
        "select * from tasks.task_table where user_id = %s order by id",
        (current_user),
    )

    result = cur.fetchall()
    tasks = []
    for row in result:
        task = {
            "id": row[0],
            "user_id": row[1],
            "title": row[2],
            "description": row[3],
            "priority": row[4],
            "due_date": row[5],
            "create_at": row[6],
            "updated_at": row[7],
        }
        tasks.append(task)
    cur.close()
    conn.close()
    return jsonify(tasks)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
