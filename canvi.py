import uno
import os
import sys
import json
import re

allData = json.load(sys.stdin)

placeholders_personals = allData['placeholders_personals']
valors_personals = allData['valors_personals']
placeholders_opcionals_personals = allData['placeholders_opcionals_personals']
valors_opcionals_personals = allData['valors_opcionals_personals']
placeholders_clients = allData['placeholders_clients']
valors_clients = allData['valors_clients']
placeholders_opcionals_clients = allData['placeholders_opcionals_clients']
valors_opcionals_clients = allData['valors_opcionals_clients']
placeholders_factura = allData['placeholders_factura']
valors_factura = allData['valors_factura']
placeholders_opcionals_factura = allData['placeholders_opcionals_factura']
valors_opcionals_factura = allData['valors_opcionals_factura']
placeholders_linia_factura = allData['placeholders_linia_factura']
valors_linia_factura = allData['valors_linia_factura']
placeholders_opcionals_linia_factura = allData['placeholders_opcionals_linia_factura']
valors_opcionals_linia_factura = allData['valors_opcionals_linia_factura']
placeholders_subtotal_linia_factura = allData['placeholders_subtotal_linia_factura']
valors_subtotal_linia_factura = allData['valors_subtotal_linia_factura']
placeholders_total_linia_factura = allData['placeholders_total_linia_factura']
valors_total_linia_factura = allData['valors_total_linia_factura']
placeholders_producte = allData['placeholders_producte']
valors_producte = allData['valors_producte']
placeholders_opcionals_producte = allData['placeholders_opcionals_producte']
valors_opcionals_producte = allData['valors_opcionals_producte']
placeholders_descomptes = allData['placeholders_descomptes']
valors_descomptes = allData['valors_descomptes']
placeholders_impostos = allData['placeholders_impostos']
valors_impostos = allData['valors_impostos']
path_usuari = allData['user_path']
dest_path = allData['dest_path']
numero_factura = allData['numero_factura']
placeholders_circumstancies = allData['placeholders_circumstancies']
dades_circumstancia = allData['dades_circumstancia']
placeholders_pagaments = allData['placeholders_pagaments']
dades_pagaments = allData['dades_pagaments']
placeholders_pagament_factura = allData['placeholders_pagament_factura']
dades_pagament_factura = allData['dades_pagament_factura']
placeholders_pagament = allData['placeholders_pagament']
dades_pagament = allData['dades_pagament']

#Cambiar '#Data_termini_Pagament' por '#Data_venciment_Pagament'
placeholders_pagament_factura = [
    '#Data_venciment_Pagament' if p == '#Data_termini_Pagament' else p
    for p in placeholders_pagament_factura
]
#Cambiar "#Compte_d'abonament_Pagament" por "#IBAN_Pagament"
placeholders_pagament = [
    '#IBAN_Pagament' if p == "#Compte_d'abonament_Pagament" else p
    for p in placeholders_pagament
]
#Eliminar '#Mitjà_de_pagament_Pagament' de placeholders_pagament_factura y su dato asociado
if '#Mitjà_de_pagament_Pagament' in placeholders_pagament_factura:
    index_to_remove = placeholders_pagament_factura.index('#Mitjà_de_pagament_Pagament')
    placeholders_pagament_factura.pop(index_to_remove)
    dades_pagament_factura.pop(index_to_remove)
total_pagaments_anticipats = 0.00
if '#Import_Pagament_Anticipat' in placeholders_pagaments:
    for idx, pag in enumerate(dades_pagaments):
        placeholders_pagaments_dict = dict(zip(placeholders_pagaments, pag))
        valor_pagament = placeholders_pagaments_dict.get('#Import_Pagament_Anticipat')
        if valor_pagament is not None:
            try:
                valor_float = round(float(valor_pagament), 2)
                total_pagaments_anticipats += valor_float
            except ValueError:
                # print(f"Error al convertir el valor a float: {valor_pagament}")
                pass
total_a_pagar = None
placeholders_pagament_factura_dict_aux = dict(zip(placeholders_pagament_factura, dades_pagament_factura))
valor_total_factura = placeholders_pagament_factura_dict_aux['#Total_Pagament']
if (valor_total_factura is not None) and (total_pagaments_anticipats > 0):
    try:
        valor_float = round(float(valor_total_factura), 2)
        total_a_pagar = valor_float - total_pagaments_anticipats
    except ValueError:
        # print(f"Error al convertir el valor a float: {valor_total_factura}")
        pass
placeholders_pagament += ['#Total_a_pagar_Pagament']
if total_a_pagar is not None:
    dades_pagament += [total_a_pagar]
else:
    dades_pagament += [valor_total_factura]
placeholders_personals_dict = dict(zip(placeholders_personals, valors_personals))
placeholders_opcionals_personals_dict = dict(zip(placeholders_opcionals_personals, valors_opcionals_personals))
placeholders_clients_dict = dict(zip(placeholders_clients, valors_clients))
placeholders_opcionals_clients_dict = dict(zip(placeholders_opcionals_clients, valors_opcionals_clients))
placeholders_factura_dict = dict(zip(placeholders_factura, valors_factura))
placeholders_opcionals_factura_dict = dict(zip(placeholders_opcionals_factura, valors_opcionals_factura))
placeholders_pagament_factura_dict = dict(zip(placeholders_pagament_factura, dades_pagament_factura))
placeholders_pagament_dict = dict(zip(placeholders_pagament, dades_pagament))
if placeholders_personals_dict['#Tipus_de_persona_Personal'] == 'Física':
    placeholders_personals_dict['#Nom_i_cognoms_o_raó_social_Personal'] = (
        placeholders_personals_dict['#Nom_i_cognoms_o_raó_social_Personal'].replace(",", "")
    )
if placeholders_clients_dict['#Tipus_de_persona_Client'] == 'Física':
    placeholders_clients_dict['#Nom_i_cognoms_o_raó_social_Client'] = (
        placeholders_clients_dict['#Nom_i_cognoms_o_raó_social_Client'].replace(",", "")
    )
# Crear un diccionario con todos los valores de las líneas de factura
placeholders_linia_factura_dict_global= {placeholder: [] for placeholder in placeholders_linia_factura}
for fila in valors_linia_factura:
    for i, placeholder in enumerate(placeholders_linia_factura):
        placeholders_linia_factura_dict_global[placeholder].append(fila[i])
placeholders_linia_factura_dict = []
# Crear un diccionario con todos los valores de las líneas de factura
placeholders_opcionals_linia_factura_global= {placeholder: [] for placeholder in placeholders_opcionals_linia_factura}
for fila in valors_opcionals_linia_factura:
    for i, placeholder in enumerate(placeholders_opcionals_linia_factura):
        placeholders_opcionals_linia_factura_global[placeholder].append(fila[i])
placeholders_opcionals_linia_factura_dict = []
# Crear un diccionario con todos los valores de las líneas de factura
placeholders_producte_global= {placeholder: [] for placeholder in placeholders_producte}
for fila in valors_producte:
    for i, placeholder in enumerate(placeholders_producte):
        placeholders_producte_global[placeholder].append(fila[i])
placeholders_producte_dict = []
# Crear un diccionario con todos los valores de las líneas de factura
placeholders_opcionals_producte_global= {placeholder: [] for placeholder in placeholders_opcionals_producte}
for fila in valors_opcionals_producte:
    for i, placeholder in enumerate(placeholders_opcionals_producte):
        placeholders_opcionals_producte_global[placeholder].append(fila[i])
placeholders_opcionals_producte_dict = []
# Crear un diccionario con todos los valores de las líneas de factura
placeholders_subtotal_linia_factura_global = {placeholder: [] for placeholder in placeholders_subtotal_linia_factura}
for fila in valors_subtotal_linia_factura:
    for i, placeholder in enumerate(placeholders_subtotal_linia_factura):
        placeholders_subtotal_linia_factura_global[placeholder].append(fila[i])
placeholders_subtotal_linia_factura_dict = []
# Crear un diccionario con todos los valores de las líneas de factura
placeholders_total_linia_factura_global = {placeholder: [] for placeholder in placeholders_total_linia_factura}
for fila in valors_total_linia_factura:
    for i, placeholder in enumerate(placeholders_total_linia_factura):
        placeholders_total_linia_factura_global[placeholder].append(fila[i])
placeholders_total_linia_factura_dict = []
# Crear un diccionario vacío con listas de listas para cada línea
placeholders_descomptes_global = {placeholder: [] for placeholder in placeholders_descomptes}
# Llenar el diccionario asegurando que cada línea tenga sus propios descuentos separados
for fila in valors_descomptes:  # Iteramos por cada línea de factura
    if fila:  # Si la línea tiene descuentos
        # Inicializamos listas vacías para los placeholders de esta línea
        placeholders_linia = {placeholder: [] for placeholder in placeholders_descomptes}
        for descuento in fila:  # Iteramos por cada descuento dentro de la línea
            for i, placeholder in enumerate(placeholders_descomptes):
                placeholders_linia[placeholder].append(descuento[i])
    else:
        # Si la línea no tiene descuentos, agregamos listas vacías
        placeholders_linia = {placeholder: [] for placeholder in placeholders_descomptes}
    # Añadimos los descuentos de esta línea al diccionario global
    for placeholder in placeholders_descomptes:
        placeholders_descomptes_global[placeholder].append(placeholders_linia[placeholder])
#print(json.dumps(placeholders_descomptes_global, indent=2, ensure_ascii=False))
placeholders_descomptes_dict = []
# Crear un diccionario vacío con listas de listas para cada línea
placeholders_impostos_global = {placeholder: [] for placeholder in placeholders_impostos}
# Llenar el diccionario asegurando que cada línea tenga sus propios imposts separados
for fila in valors_impostos:  # Iteramos por cada línea de factura
    if fila:  # Si la línea tiene imposts
        # Inicializamos listas vacías para los placeholders de esta línea
        placeholders_linia = {placeholder: [] for placeholder in placeholders_impostos}
        for impost in fila:  # Iteramos por cada impost dentro de la línea
            for i, placeholder in enumerate(placeholders_impostos):
                placeholders_linia[placeholder].append(impost[i])
    else:
        # Si la línea no tiene imposts, agregamos listas vacías
        placeholders_linia = {placeholder: [] for placeholder in placeholders_impostos}
    # Añadimos los imposts de esta línea al diccionario global
    for placeholder in placeholders_impostos:
        placeholders_impostos_global[placeholder].append(placeholders_linia[placeholder])
#print(json.dumps(placeholders_impostos_global, indent=2, ensure_ascii=False))
placeholders_impostos_dict = []
#linia_actual es un index que nos dice por que fila vamos en placeholders_linia_factura_dict_global
linia_actual = 0
#sumar_linia es un flag que nos dice si tenemos que sumar una linia a linia_actual por pasar a la siguiente linia
sumar_linia = 0
valors_primera_linia_factura = []
# Combinar todos los diccionarios en uno solo
placeholders_dict = {
    **placeholders_personals_dict,
    **placeholders_opcionals_personals_dict,
    **placeholders_clients_dict,
    **placeholders_opcionals_clients_dict,
    **placeholders_factura_dict,
    **placeholders_opcionals_factura_dict,
    **placeholders_pagament_factura_dict,
    **placeholders_pagament_dict,
}

def obtener_linia_plantilla(tabla, fila):
    global valors_primera_linia_factura  # ⬅ Ahora sí modificamos las variables globales
    for columna in range(tabla.Columns.Count):
        valors_primera_linia_factura.append(tabla.getCellByPosition(columna, fila).getString())
    #print(f"Valors primera linia factura actualitzats: {valors_primera_linia_factura}")
    
def afegir_linia_plantilla(tabla, fila):
    global valors_primera_linia_factura  # ⬅ Ahora sí modificamos las variables globales
    #print(f"linia_actual: {linia_actual}, len(valors_linia_factura)-1 {len(valors_linia_factura)-1}")
    if tabla != None:
        #Mirar si existe una fila mas en la tabla, si no existe, la creamos
        filas_disponibles = tabla.Rows.getCount() - 1
        #print(f"Tabla: {tabla.Name}, Fila: {fila}, filas disponibles: {filas_disponibles}")
        if (fila+1) > filas_disponibles:
            tabla.Rows.insertByIndex(fila+1, 1)
            for columna in range(tabla.Columns.Count):
                texto_original = valors_primera_linia_factura[columna]
                #print(f"Texto original: {texto_original}")
                celda = tabla.getCellByPosition(columna, fila+1)
                celda.setString(texto_original)
            # Eliminar bordes internos, manteniendo solo los exteriores
            #bordes_tabla = taula_personal.TableBorder2
            #empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
            #bordes_tabla.HorizontalLine = empty_line  # Eliminar bordes horizontales internos
            #bordes_tabla.VerticalLine = empty_line  # Eliminar bordes verticales internos
            #taula_personal.TableBorder2 = bordes_tabla
            
def substituir_descomptes(texto):
    global placeholders_descomptes_dict
    textos_sustituidos = []
    #print(f"desc_dict: {placeholders_descomptes_dict}")
    # Obtener el número de descuentos en esta línea
    num_descomptes = len(next(iter(placeholders_descomptes_dict.values()), []))
    for i in range(num_descomptes):
        # Crear un diccionario con solo los valores del descuento actual (índice `i`)
        dicc_descompte_individual = {
            placeholder: placeholders_descomptes_dict[placeholder][i] 
            for placeholder in placeholders_descomptes
        }
        #print(f"dicc_descompte_individual: {dicc_descompte_individual}")
        # Sustituir placeholders en el texto
        texto_modificado = texto
        for placeholder, valor in dicc_descompte_individual.items():
            if valor is None:
                valor = "-"
            else:
                valor = str(valor)
            texto_modificado = texto_modificado.replace(placeholder, valor)
        textos_sustituidos.append(texto_modificado)
        #textos_sustituidos.append(texto_modificado)
    # Unir los textos con saltos de línea y asignarlos al objeto
    texto_final = "\n".join(textos_sustituidos)
    #print(f"Texto final: {texto_final}")
    return texto_final
 
def substituir_impostos(texto):
    global placeholders_impostos_dict
    textos_sustituidos = []
    #print(f"imp_dict: {placeholders_impostos_dict}")
    # Obtener el número de impostos en esta línea
    num_impostos = len(next(iter(placeholders_impostos_dict.values()), []))
    for i in range(num_impostos):
        # Crear un diccionario con solo los valores del impost actual (índice `i`)
        dicc_impost_individual = {
            placeholder: placeholders_impostos_dict[placeholder][i] 
            for placeholder in placeholders_impostos
        }
        #print(f"dicc_impost_individual: {dicc_impost_individual}")
        # Sustituir placeholders en el texto
        texto_modificado = texto
        for placeholder, valor in dicc_impost_individual.items():
            if valor is None:
                valor = "-"
            else:
                valor = str(valor)
            texto_modificado = texto_modificado.replace(placeholder, valor)
        textos_sustituidos.append(texto_modificado)
        #textos_sustituidos.append(texto_modificado)
    # Unir los textos con saltos de línea y asignarlos al objeto
    texto_final = "\n".join(textos_sustituidos)
    #print(f"Texto final: {texto_final}")
    return texto_final

def sustituir_texto(objeto, tabla, fila, columna):
    """ Reemplaza los placeholders en un objeto de texto si es posible. """
    global linia_actual, sumar_linia, valors_primera_linia_factura, placeholders_linia_factura_dict, placeholders_opcionals_linia_factura_dict, placeholders_producte_dict, placeholders_opcionals_producte_dict, placeholders_subtotal_linia_factura_dict, placeholders_total_linia_factura_dict, placeholders_descomptes_dict, placeholders_impostos_dict, placeholders_circumstancies, dades_circumstancia, placeholders_pagaments, dades_pagaments # ⬅ Ahora sí modificamos las variables globales
    if hasattr(objeto, "getString"):
        texto = objeto.getString()
        # Encontrar todos los placeholders en el texto
        placeholders_encontrados = re.findall(r'#\S+', texto)
        descomptes_modificats = False
        impostos_modificats = False
        condicions_modificades = False
        pagaments_modificats = False
        for placeholder in placeholders_encontrados:
            if placeholder in placeholders_dict:
                valor = placeholders_dict[placeholder]  # Obtener el valor asociado
                #print(f"{placeholder} está en el diccionario con valor: {valor}")
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor)
                texto = texto.replace(placeholder, valor)
                objeto.setString(texto)
            elif placeholder in placeholders_linia_factura:
                #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                sumar_linia = 1
                #print(f"Modificar sumar_linia: {sumar_linia}")
                if len(valors_primera_linia_factura) == 0:
                    obtener_linia_plantilla(tabla, fila)
                if linia_actual < len(valors_linia_factura)-1:
                    afegir_linia_plantilla(tabla, fila)
                #print(f"{placeholder} está en el diccionario con valor: {valor}")
                valor = placeholders_linia_factura_dict[placeholder]  #Texto de prueba
                #print(tabla.Name, linia_actual, placeholders_linia_factura_dict[placeholder])  
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor)
                texto = texto.replace(placeholder, valor)
                objeto.setString(texto)
            elif placeholder in placeholders_opcionals_linia_factura:
                #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                sumar_linia = 1
                #print(f"Modificar sumar_linia: {sumar_linia}")
                if len(valors_primera_linia_factura) == 0:
                    obtener_linia_plantilla(tabla, fila)
                if linia_actual < len(valors_linia_factura)-1:
                    afegir_linia_plantilla(tabla, fila)
                #print(f"{placeholder} está en el diccionario con valor: {valor}")
                valor = placeholders_opcionals_linia_factura_dict[placeholder]  #Texto de prueba
                #print(tabla.Name, linia_actual, placeholders_opcionals_linia_factura_dict[placeholder]) 
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor) 
                texto = texto.replace(placeholder, valor)
                objeto.setString(texto)
            elif placeholder in placeholders_producte:
                #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                sumar_linia = 1
                #print(f"Modificar sumar_linia: {sumar_linia}")
                if len(valors_primera_linia_factura) == 0:
                    obtener_linia_plantilla(tabla, fila)
                if linia_actual < len(valors_linia_factura)-1:
                    afegir_linia_plantilla(tabla, fila)
                #print(f"{placeholder} está en el diccionario con valor: {valor}")
                valor = placeholders_producte_dict[placeholder]  #Texto de prueba
                #print(tabla.Name, linia_actual, placeholders_producte_dict[placeholder])  
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor)
                texto = texto.replace(placeholder, valor)
                objeto.setString(texto)
            elif placeholder in placeholders_opcionals_producte:
                #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                sumar_linia = 1
                #print(f"Modificar sumar_linia: {sumar_linia}")
                if len(valors_primera_linia_factura) == 0:
                    obtener_linia_plantilla(tabla, fila)
                if linia_actual < len(valors_linia_factura)-1:
                    afegir_linia_plantilla(tabla, fila)
                #print(f"{placeholder} está en el diccionario con valor: {valor}")
                valor = placeholders_opcionals_producte_dict[placeholder]  #Texto de prueba
                #print(tabla.Name, linia_actual, placeholders_opcionals_producte_dict[placeholder])  
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor)
                texto = texto.replace(placeholder, valor)
                objeto.setString(texto)
            elif placeholder in placeholders_subtotal_linia_factura:
                #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                sumar_linia = 1
                #print(f"Modificar sumar_linia: {sumar_linia}")
                if len(valors_primera_linia_factura) == 0:
                    obtener_linia_plantilla(tabla, fila)
                if linia_actual < len(valors_linia_factura)-1:
                    afegir_linia_plantilla(tabla, fila)
                #print(f"{placeholder} está en el diccionario con valor: {valor}")
                valor = placeholders_subtotal_linia_factura_dict[placeholder]  #Texto de prueba
                #print(tabla.Name, linia_actual, placeholders_subtotal_linia_factura_dict[placeholder])  
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor)
                texto = texto.replace(placeholder, valor)
                objeto.setString(texto)
            elif placeholder in placeholders_total_linia_factura:
                #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                sumar_linia = 1
                #print(f"Modificar sumar_linia: {sumar_linia}")
                if len(valors_primera_linia_factura) == 0:
                    obtener_linia_plantilla(tabla, fila)
                if linia_actual < len(valors_linia_factura)-1:
                    afegir_linia_plantilla(tabla, fila)
                #print(f"{placeholder} está en el diccionario con valor: {valor}")
                valor = placeholders_total_linia_factura_dict[placeholder]  #Texto de prueba
                #print(tabla.Name, linia_actual, placeholders_total_linia_factura_dict[placeholder])  
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor)
                texto = texto.replace(placeholder, valor)
                objeto.setString(texto)  
            elif placeholder in placeholders_descomptes :
                if not descomptes_modificats:
                    #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                    sumar_linia = 1
                    #print(f"Modificar sumar_linia: {sumar_linia}")
                    if len(valors_primera_linia_factura) == 0:
                        obtener_linia_plantilla(tabla, fila)
                    if linia_actual < len(valors_linia_factura)-1:
                        afegir_linia_plantilla(tabla, fila)
                    #print(f"{placeholder} está en el diccionario con valor: {valor}")
                    texto_final = substituir_descomptes(texto)
                    #print(f"Texto final descompte: {texto_final}")
                    objeto.setString(texto_final)
                    descomptes_modificats = True
            elif placeholder in placeholders_impostos :
                if not impostos_modificats:
                    #Como hemos encontrado un elemento de la fila de la factura, sumamos una linia que se efectuara en el seiguiente bucle de la tabla  en la siguiente fila
                    sumar_linia = 1
                    #print(f"Modificar sumar_linia: {sumar_linia}")
                    if len(valors_primera_linia_factura) == 0:
                        obtener_linia_plantilla(tabla, fila)
                    if linia_actual < len(valors_linia_factura)-1:
                        afegir_linia_plantilla(tabla, fila)
                    #print(f"{placeholder} está en el diccionario con valor: {valor}")
                    texto_final = substituir_impostos(texto)
                    #print(f"Texto final impost: {texto_final}")
                    objeto.setString(texto_final)
                    impostos_modificats = True
            elif placeholder in placeholders_circumstancies:
                if not condicions_modificades:
                    texto_circumstancies = objeto.getString()
                    texto_circumstancies_final = ""
                    total_circumstancies = len(dades_circumstancia)
                    for idx, circ in enumerate(dades_circumstancia):
                        placeholders_circumstancies_dict = dict(zip(placeholders_circumstancies, circ))
                        texto_circ = texto_circumstancies
                        placeholders_encontrados_circ = re.findall(r'#\S+', texto_circ)
                        for placeholder_circ in placeholders_encontrados_circ:
                            valor_circ = placeholders_circumstancies_dict.get(placeholder_circ, "")
                            texto_circ = texto_circ.replace(placeholder_circ, valor_circ)
                        texto_circumstancies_final += texto_circ
                        if idx < total_circumstancies - 1:
                            texto_circumstancies_final += "\n"  # Solo añadir \n si **no** es el último
                    objeto.setString(texto_circumstancies_final)
                    condicions_modificades = True
            elif placeholder in placeholders_pagaments:
                if not pagaments_modificats:
                    texto_pagaments = objeto.getString()
                    texto_pagaments_final = ""
                    total_pagaments = len(dades_pagaments)
                    for idx, pag in enumerate(dades_pagaments):
                        placeholders_pagaments_dict = dict(zip(placeholders_pagaments, pag))
                        texto_pag = texto_pagaments
                        placeholders_encontrados_pag = re.findall(r'#\S+', texto_pag)
                        for placeholder_pag in placeholders_encontrados_pag:
                            valor_pag = placeholders_pagaments_dict.get(placeholder_pag, "")
                            texto_pag = texto_pag.replace(placeholder_pag, valor_pag)
                        texto_pagaments_final += texto_pag
                        if idx < total_pagaments - 1:
                            texto_pagaments_final += "\n"  # Solo añadir \n si **no** es el último
                    objeto.setString(texto_pagaments_final)
                    pagaments_modificats = True
            else:
                #print(f"{placeholder} NO está en el diccionario")
                if valor is None:
                    valor = ""
                else:
                    valor = str(valor)
                texto = texto.replace(placeholder, "")
                objeto.setString(texto)
    if hasattr(objeto, "getCount"):
        try:
            for i in range(objeto.getCount()):
                sustituir_texto(objeto.getByIndex(i), None, None, None)
        except Exception:
            pass  # Evitar errores al recorrer elementos

def sustituir_texto_tabla(tabla, celdas_procesadas):
    """ Reemplaza placeholders en una tabla evitando modificar celdas de tablas anidadas. """
    global linia_actual, sumar_linia, valors_primera_linia_factura, placeholders_linia_factura_dict, placeholders_opcionals_linia_factura_dict, placeholders_producte_dict, placeholders_opcionals_producte_dict, placeholders_subtotal_linia_factura_dict, placeholders_total_linia_factura_dict, placeholders_descomptes_dict, placeholders_impostos_dict # ⬅ Ahora sí modificamos las variables globales
    fila = 0
    while fila < tabla.Rows.Count:
        #print(f"Llegir sumar_linia: {sumar_linia}")
        #Si sumar_linia es 1, sumamos una linia a linia_actual, y reseteamos el flag
        if sumar_linia == 1:
            linia_actual += 1
            sumar_linia = 0
        # Crear un diccionario con solo el primer valor de cada placeholder, es decir este tendra los valores de la linea actualñ apuntada por el indice linia_actual
        placeholders_linia_factura_dict = {k: v[linia_actual] for k, v in placeholders_linia_factura_dict_global.items()} 
        placeholders_opcionals_linia_factura_dict = {k: v[linia_actual] for k, v in placeholders_opcionals_linia_factura_global.items()}
        placeholders_producte_dict = {k: v[linia_actual] for k, v in placeholders_producte_global.items()}
        placeholders_opcionals_producte_dict = {k: v[linia_actual] for k, v in placeholders_opcionals_producte_global.items()}
        placeholders_subtotal_linia_factura_dict = {k: v[linia_actual] for k, v in placeholders_subtotal_linia_factura_global.items()}
        placeholders_total_linia_factura_dict = {k: v[linia_actual] for k, v in placeholders_total_linia_factura_global.items()}
        placeholders_descomptes_dict = {
            placeholder: placeholders_descomptes_global[placeholder][linia_actual]
            for placeholder in placeholders_descomptes
        }
        #print(f"placeholders_descomptes_dict: {placeholders_descomptes_dict}")
        placeholders_impostos_dict = {
            placeholder: placeholders_impostos_global[placeholder][linia_actual]
            for placeholder in placeholders_impostos
        }
        #print(f"placeholders_impostos_dict: {placeholders_impostos_dict}")        
        #print(tabla.Name, linia_actual, placeholders_linia_factura_dict)
        columna = 0
        while columna < tabla.Columns.Count:
            try:
                if fila >= tabla.Rows.Count or columna >= tabla.Columns.Count:
                    #print(f"Celda fuera de rango ({tabla.Name}, {fila}, {columna}), omitiendo.")
                    continue
                celda = tabla.getCellByPosition(columna, fila)
                # Verificar si la celda tiene una tabla anidada
                enumeration = celda.Text.createEnumeration()
                while enumeration.hasMoreElements():
                    element = enumeration.nextElement()
                    if element.supportsService("com.sun.star.text.TextTable"):
                        #print(f"Celda ({tabla.Name}, {fila}, {columna}) contiene una tabla anidada, omitiendo.")
                        break
                else:  # Solo entra aquí si no hay una tabla anidada
                    if celda not in celdas_procesadas:
                        sustituir_texto(celda, tabla, fila, columna)
                        celdas_procesadas.add(celda)
            except Exception as e:
                #print(f"Error en celda ({tabla.Name}, {fila}, {columna}): {e}")
                pass
            columna += 1
        fila += 1
        
def sustituir_texto_en_documento(document):
    """ Reemplaza los placeholders en todo el documento, incluyendo texto y tablas. """
    global linia_actual, sumar_linia, valors_primera_linia_factura
    sustituir_texto(document.Text, None, None, None)
    celdas_procesadas = set()
    try:
        for tabla in document.TextTables:
            linia_actual = 0
            sumar_linia = 0
            valors_primera_linia_factura = []
            sustituir_texto_tabla(tabla, celdas_procesadas)
    except Exception:
        pass

def main():
    plantilla_path = os.path.join(path_usuari, "plantilla_personal.odt")
    factura_path = os.path.join(dest_path, numero_factura+".odt")
    file_url = uno.systemPathToFileUrl(plantilla_path)
    factura_url = uno.systemPathToFileUrl(factura_path)
    local_context = uno.getComponentContext()
    resolver = local_context.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local_context)
    ctx = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext")
    smgr = ctx.ServiceManager
    desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", ctx) 
    document = desktop.loadComponentFromURL(file_url, "_blank", 0, ())
    if not document:
        #print("Error: No se pudo cargar el documento.")
        sys.exit(1)
    sustituir_texto_en_documento(document)
    document.storeAsURL(factura_url, ())
    # Guardar el documento en PDF
    output_path_pdf = os.path.join(dest_path, numero_factura+".pdf")
    output_url_pdf = uno.systemPathToFileUrl(output_path_pdf)
    pdf_properties = (
        uno.createUnoStruct("com.sun.star.beans.PropertyValue", Name="FilterName", Value="writer_pdf_Export"),
        uno.createUnoStruct("com.sun.star.beans.PropertyValue", Name="Overwrite", Value=True),
    )
    document.storeToURL(output_url_pdf, pdf_properties)
    document.close(True)
    #print(json.dumps({"message": "Documento modificado y guardado con éxito"}))
    sys.exit(0)

if __name__ == "__main__":
    main()