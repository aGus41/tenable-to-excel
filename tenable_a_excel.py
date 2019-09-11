import pandas as pd
from pandas import ExcelWriter
import time
import requests
import json
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


def get_ip_externas(rows, rows_length):
    ip_externas = []
    for i in range(rows_length):
        ip_externa = rows[i][2]
        ip_externas.append(ip_externa)
    return ip_externas


def get_fqdn_ext(rows, rows_length):
    fqdn_externos = []
    for i in range(rows_length):
        fqdn_ext = rows[i][0]
        fqdn_externos.append(fqdn_ext)
    return fqdn_externos


def get_responsables(rows, rows_length):
    responsables = []
    for i in range(rows_length):
        responsable = rows[i][6]
        responsables.append(responsable)
    return responsables


def tenable_csv_request(my_headers, scan_name):
    r_scans = requests.get('https://cloud.tenable.com/scans',
                           headers={"X-ApiKeys": my_headers})

    scan_json = json.loads(r_scans.text)

    for i in range(len(scan_json)):
        if scan_json[i]['name'] == scan_name:
            scan_id = scan_json[i]['id']
        elif i == len(scan_json) - 1:
            print('scan not found')
            exit()

    print(scan_id)
    r_exportrequest = requests.post("https://cloud.tenable.com/scans/" +
                                    scan_id + "/export", data={'format': 'csv',
                                                               'asset_id': 1, 'chapters': 'vuln_hosts_summary'},
                                    headers={"X-ApiKeys": my_headers})

    file_id = json.loads(r_exportrequest.text)[0]['file']

    print(file_id)
    r_csv = requests.get('https://cloud.tenable.com/scans/' + scan_id + '/export/' + file_id + '/download',
                         headers={"X-ApiKeys": my_headers})
    time.sleep(5)
    open(scan_name.replace(":", "") + '.csv', 'wb').write(r_csv.content)
    return scan_name, r_csv


def get_responsables_ip_tenable(ip_tenable, dict_ipext_responsables_rangocompleto):
    lista_responsables = [None] * len(ip_tenable)
    for i in range(len(ip_tenable)):
        lista_responsables[i] = dict_ipext_responsables_rangocompleto.pop(ip_tenable[i],
                                                                          "Host no registrado en la base de datos")
    return lista_responsables, dict_ipext_responsables_rangocompleto


def get_fqdnhostsinactivos(dict_host_en_desuso):
    dict_f = dict(zip(get_ip_externas(), get_fqdn_ext()))
    fqdn_hostsinactivos = [None] * len(list(dict_host_en_desuso.keys()))
    for i in range(len(list(dict_host_en_desuso.keys()))):
        fqdn_hostsinactivos[i] = dict_f.get(list(dict_host_en_desuso.keys())[i])
    return fqdn_hostsinactivos


def color_hostnoregistrado(val):
    color = 'orange' if val == "Host no registrado en la base de datos" or val == '' else 'white'
    return 'background-color: %s' % color


def main():
    access_key = 'key'
    secret_key = "key"
    my_headers = "accessKey=" + access_key + "; secretKey=" + secret_key

    scan_name = "<scan_name>"
    scan_name, r_csv = tenable_csv_request(my_headers, scan_name)
    df = pd.read_csv(scan_name.replace(":", "") + '.csv')
    print(scan_name.replace(":", "") + '.csv')  # illegal char ':'

    rows, rows_lenght = calambuco_inventario()

    dict_ipext_responsables_rangocompleto = dict(
        zip(get_ip_externas(rows, rows_lenght), get_responsables(rows, rows_lenght)))

    df.drop(['IP Address', 'Plugin ID', 'Risk', 'CVE', 'CVSS', 'Protocol', 'Port', 'Name', 'Synopsis', 'Description',
             'Solution', 'See Also', 'Plugin Output',
             'Asset UUID', 'Vulnerability State', 'NetBios', 'OS',
             'MAC Address', 'Plugin Family', 'CVSS Base Score',
             'CVSS Temporal Score', 'CVSS Temporal Vector', 'CVSS Vector',
             'CVSS3 Base Score', 'CVSS3 Temporal Score',
             'CVSS3 Temporal Vector', 'CVSS3 Vector', 'System Type',
             'Host Start', 'Host End'], axis=1, inplace=True)

    df.drop_duplicates(keep='first', inplace=True)
    df.sort_values(by='Host', ascending=True, inplace=True)

    index_ips_tenable = df.loc[:, 'Host']
    ip_tenable = index_ips_tenable.values.tolist()

    lista_responsables, dict_host_en_desuso = get_responsables_ip_tenable(ip_tenable,
                                                                          dict_ipext_responsables_rangocompleto)

    writer = ExcelWriter(scan_name.replace(":", "") + '_hostsactivos' + '.xlsx')

    if scan_name == 'Publicas TID F5: 195.235.92.128-255':
        df = df.assign(Responsable=lista_responsables)
        df = df.style.applymap(color_hostnoregistrado)
        df.to_excel(writer, 'Hosts Activos', index=False)
        df2 = pd.DataFrame(list(dict_host_en_desuso.keys()), columns=['Host'])
        df2 = df2.assign(FQDN=get_fqdnhostsinactivos(dict_host_en_desuso))
        df2 = df2.assign(Responsable=list(dict_host_en_desuso.values()))
        df2.to_excel(writer, 'Hosts Inactivos', index=False)


    else:
        df.to_excel(writer, 'Hosts Activos', index=False)

    writer.save()
    print(scan_name.replace(":", "") + '_hostsactivos' + '.xlsx')
    print('Host Activos: detectados por el scaner de tenable.\nHosts inactivos: hosts que están registrados en la base '
          'de datos no detectados por el tenable')


if __name__ == '__main__':
    main()
