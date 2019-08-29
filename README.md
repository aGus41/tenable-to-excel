Gets a vulnerability scan in csv format through tenable API and checks it against an internal database. Show results in excel using pandas


---

Crea un excel con los datos del escaner del tenable. 

	Host Activos: detectados por el scaner de tenable.
	Hosts inactivos: hosts que están registrados en la base de datos pero que no los detecta el tenable

En ambas pestañas se añade una columna con los Responsables de esas publicaciones (lo que esté registrados en la base de datos f5 de inventario en ese campo). 
En caso de que los hosts detectados por tenable no estén en la base de datos, la columna de responsable 
se rellana con 'Host no registrado en la base de datos'.

Se puede cambiar el valor de scan_name en requests_api para que se haga la requests sobre otros escaners del tenable.

Posible mejora: añadir una entrada a la base de datos con los Hosts nuevos


