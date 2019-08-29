import mysql.connector
from mysql.connector import Error


def calambuco_inventario():
    query = ("SELECT * FROM f5 ORDER BY ip_externa")

    try:
        conn = mysql.connector.connect(user='inventory', password='password', host='host',
                                       # Conectarme a la base de datos inventario
                                       database='inventario')
        # Creamos el cursor
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        rows_lenght = len(rows)

    except Error as error:
        raise error
    finally:
        cursor.close()
        conn.close()
    return rows, rows_lenght


rows, rows_lenght = calambuco_inventario()

ip_externas = []
fqdn_externos = []
responsables = []


def get_ip_externas():
    for i in range(0, rows_lenght):
        ip_externa = rows[i][2]
        ip_externas.append(ip_externa)
    return ip_externas


def get_fqdn_ext():
    for i in range(0, rows_lenght):
        fqdn_ext = rows[i][0]
        fqdn_externos.append(fqdn_ext)
    return fqdn_externos


def get_responsables():
    for i in range(0, rows_lenght):
        responsable = rows[i][6]
        responsables.append(responsable)
    return responsables
