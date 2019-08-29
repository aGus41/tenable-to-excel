# coding=utf-8
import pandas as pd
from pandas import ExcelWriter
from requests_api import tenable_csv_request
from mysql_inventario import get_ip_externas, get_fqdn_ext, get_responsables

scan_name, r_csv = tenable_csv_request()
df = pd.read_csv(scan_name.replace(":", "") + '.csv')
print(scan_name.replace(":", "") + '.csv')  # illegal char ':'


dict_ipext_responsables_rangocompleto = dict(zip(get_ip_externas(), get_responsables()))

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


def get_responsables_ip_tenable():
    lista_responsables = [None] * len(ip_tenable)
    for i in range(0, len(ip_tenable)):
        lista_responsables[i] = dict_ipext_responsables_rangocompleto.pop(ip_tenable[i],
                                                                          "Host no registrado en la base de datos")
    return lista_responsables, dict_ipext_responsables_rangocompleto


lista_responsables, dict_host_en_desuso = get_responsables_ip_tenable()

writer = ExcelWriter(scan_name.replace(":", "") + '_hostsactivos' + '.xlsx')


def get_fqdnhostsinactivos():
    dict_f = dict(zip(get_ip_externas(), get_fqdn_ext()))
    fqdn_hostsinactivos = [None] * len(list(dict_host_en_desuso.keys()))
    for i in range(0, len(list(dict_host_en_desuso.keys()))):
        fqdn_hostsinactivos[i] = dict_f.get(list(dict_host_en_desuso.keys())[i])
    return fqdn_hostsinactivos


def color_hostnoregistrado(val):
    color = 'orange' if val == "Host no registrado en la base de datos" or val == '' else 'white'
    return 'background-color: %s' % color


if scan_name == 'Publicas TID F5: 195.235.92.128-255':
    df = df.assign(Responsable=lista_responsables)
    df = df.style.applymap(color_hostnoregistrado)
    df.to_excel(writer, 'Hosts Activos', index=False)
    df2 = pd.DataFrame(list(dict_host_en_desuso.keys()), columns=['Host'])
    df2 = df2.assign(FQDN=get_fqdnhostsinactivos())
    df2 = df2.assign(Responsable=list(dict_host_en_desuso.values()))
    df2.to_excel(writer, 'Hosts Inactivos', index=False)


else:
    df.to_excel(writer, 'Hosts Activos', index=False)

writer.save()
print(scan_name.replace(":", "") + '_hostsactivos' + '.xlsx')
print('Host Activos: detectados por el scaner de tenable.\nHosts inactivos: hosts que están registrados en la base '
      'de datos no detectados por el tenable')
