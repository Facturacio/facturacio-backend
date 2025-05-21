import uno
import os
import sys
import json

allData = json.load(sys.stdin)

valors_personals = allData['valors_personals']
valors_opcionals_personals = allData['valors_opcionals_personals']
valors_clients = allData['valors_clients']
valors_opcionals_clients = allData['valors_opcionals_clients']
camps_factura = allData['camps_factura']
valors_factura = allData['valors_factura']
camps_opcionals_factura = allData['camps_opcionals_factura']
valors_opcionals_factura = allData['valors_opcionals_factura']
camps_linia_factura = allData['camps_linia_factura']
valors_linia_factura = allData['valors_linia_factura']
camps_opcionals_linia_factura = allData['camps_opcionals_linia_factura']
valors_opcionals_linia_factura = allData['valors_opcionals_linia_factura']
camps_producte = allData['camps_producte']
valors_producte = allData['valors_producte']
camps_opcionals_producte = allData['camps_opcionals_producte']
valors_opcionals_producte = allData['valors_opcionals_producte']
camps_descomptes = allData['camps_descomptes']
valors_descomptes = allData['valors_descomptes']
camps_impostos = allData['camps_impostos']
valors_impostos = allData['valors_impostos']
camps_pagament_factura = allData['camps_pagament_factura']
valors_pagament_factura = allData['valors_pagament_factura']
camps_circumstancies = allData['camps_circumstancies']
valors_circumstancies = allData['valors_circumstancies']
camps_pagaments = allData['camps_pagaments']
valors_pagaments = allData['valors_pagaments']
camps_pagament = allData['camps_pagament']
valors_pagament = allData['valors_pagament'] 
path_usuari = allData['user_path']

if "Unitats" in camps_producte:
    # Si existe el campo "Unitats" en camps_producte, eliminarlo de camps_producte y valors_producte (manteniendo el mismo índice)
    index_unitats = camps_producte.index("Unitats")
    camps_producte.pop(index_unitats)
    placeholder_unitats = " " + valors_producte.pop(index_unitats)  # Extraer y eliminar en una sola línea
    # Agregar la cantidad de la línea de factura si existe "Quantitat" en camps_linia_factura
    if "Quantitat" in camps_linia_factura:
        index_quantitat = camps_linia_factura.index("Quantitat")
        valors_linia_factura[index_quantitat] += placeholder_unitats  # Concatenar los valores correctamente

if "Preu unitari" in camps_linia_factura:
    # Si existe el campo "Unitats" en camps_producte, eliminarlo de camps_producte y valors_producte (manteniendo el mismo índice)
    index_preu = camps_linia_factura.index("Preu unitari")
    valors_linia_factura[index_preu] += " €"  # Concatenar los valores correctamente

# Ordenar manteniendo la relación entre ambos arrays
camps_linia_factura, valors_linia_factura = zip(*sorted(zip(camps_linia_factura, valors_linia_factura)))
# Convertir de nuevo a listas
camps_linia_factura = list(camps_linia_factura)
valors_linia_factura = list(valors_linia_factura)
camps_linia_factura += ['Descomptes', 'Subtotal', 'Impostos', 'Total']
valors_linia_factura += ['Descomptes', '#Subtotal_Linia €', 'Impostos', '#Total_Linia €']
camps_descomptes += ['Total'] 
valors_descomptes += ['#Total_Descompte_Linia']
camps_impostos += ['Total'] 
valors_impostos += ['#Total_Impost_Linia']
camps_pagament_factura += ['Total a pagar']
valors_pagament_factura += ['#Total_a_pagar_Pagament']

# Conexión a LibreOffice en modo servidor
local_context = uno.getComponentContext()
resolver = local_context.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local_context)
context = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext")
desktop = context.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", context)

# Obtener la ruta del archivo que queremos modificar
script_path = os.path.dirname(os.path.abspath(__file__))
input_path = os.path.join(script_path, "plantilla_general.odt")
file_url = uno.systemPathToFileUrl(input_path)
document = desktop.loadComponentFromURL(file_url, "_blank", 0, ())

# Función para aplicar el estilo de fuente, tamaño y negrita a un cursor de texto en una celda
def aplicar_estilo_a_cursor(cursor, fuente="Arial", tamano=10, negrita=False):
    cursor.CharFontName = fuente
    cursor.CharHeight = tamano
    cursor.CharWeight = uno.getConstantByName("com.sun.star.awt.FontWeight.BOLD") if negrita else uno.getConstantByName("com.sun.star.awt.FontWeight.NORMAL")

# Función para insertar datos en una única celda y aplicar estilos
def insertar_datos_en_celda_con_estilo(celda, datos, negrita_items=[], negrita_forced = False):
    cursor = celda.createTextCursor()
    for i, dato in enumerate(datos):  # Asegurarse de que 'datos' es una lista
        aplicar_estilo_a_cursor(cursor, fuente="Arial", tamano=10, negrita=(dato in negrita_items or negrita_forced))
        celda.insertString(cursor, dato, False)
        if i < len(datos) - 1:
            celda.insertString(cursor, "\n", False)

# Insertar datos en la tabla "Taula_personal"
if document.TextTables.hasByName("Taula_personal"):
    taula_personal = document.TextTables.getByName("Taula_personal")
    # Insertar tantas filas como datos personales haya
    num_filas_actuales = taula_personal.Rows.getCount()
    taula_personal.Rows.insertByIndex(num_filas_actuales, len(valors_personals) + len(valors_opcionals_personals) - 1)
    # Eliminar bordes internos, manteniendo solo los exteriores
    bordes_tabla = taula_personal.TableBorder2
    empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    bordes_tabla.HorizontalLine = empty_line  # Eliminar bordes horizontales internos
    bordes_tabla.VerticalLine = empty_line  # Eliminar bordes verticales internos
    taula_personal.TableBorder2 = bordes_tabla
    # Insertar datos en cada fila correctamente
    for i in range(len(valors_personals)):
        cel_personal = taula_personal.getCellByPosition(0, i)
        negrita = False
        if i == 0: 
            negrita = True
        insertar_datos_en_celda_con_estilo(cel_personal, [valors_personals[i]], negrita_items=["Nom_personal_personal"], negrita_forced = negrita)
    for i in range(len(valors_opcionals_personals)):
        cel_personal = taula_personal.getCellByPosition(0, len(valors_personals) + i)
        insertar_datos_en_celda_con_estilo(cel_personal, [valors_opcionals_personals[i]], negrita_items=[], negrita_forced = False)
        
if document.TextTables.hasByName("Taula_client"):
    taula_client = document.TextTables.getByName("Taula_client")
    # Insertar tantas filas como datos personales haya
    num_filas_actuales = taula_client.Rows.getCount()
    taula_client.Rows.insertByIndex(num_filas_actuales, len(valors_clients) + len(valors_opcionals_clients) - 1)
    # Eliminar bordes internos, manteniendo solo los exteriores
    bordes_tabla = taula_client.TableBorder2
    empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    bordes_tabla.HorizontalLine = empty_line  # Eliminar bordes horizontales internos
    bordes_tabla.VerticalLine = empty_line  # Eliminar bordes verticales internos
    taula_client.TableBorder2 = bordes_tabla
    # Insertar datos en cada fila correctamente
    for i in range(len(valors_clients)):
        cel_clients = taula_client.getCellByPosition(0, i)
        negrita = False
        if i == 0: 
            negrita = True
        insertar_datos_en_celda_con_estilo(cel_clients, [valors_clients[i]], negrita_items=["Nom_complet_client"], negrita_forced = negrita)
    for i in range(len(valors_opcionals_clients)):
        cel_client = taula_client.getCellByPosition(0, len(valors_personals) + i)
        insertar_datos_en_celda_con_estilo(cel_client, [valors_opcionals_clients[i]], negrita_items=[], negrita_forced = False)
     
if document.TextTables.hasByName("dades_factura"):
    taula_dades_factura = document.TextTables.getByName("dades_factura")
    # Insertar tantas filas como datos personales haya
    num_filas_actuales = taula_dades_factura.Rows.getCount()
    taula_dades_factura.Rows.insertByIndex(num_filas_actuales, len(camps_factura) + len(camps_opcionals_factura) - 1)
    # Eliminar bordes internos, manteniendo solo los exteriores
    bordes_tabla = taula_dades_factura.TableBorder2
    empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    bordes_tabla.HorizontalLine = empty_line  # Eliminar bordes horizontales internos
    bordes_tabla.VerticalLine = empty_line  # Eliminar bordes verticales internos
    taula_dades_factura.TableBorder2 = bordes_tabla
    # Insertar datos en cada fila correctamente
    for i in range(len(camps_factura)):
        cel_clients = taula_dades_factura.getCellByPosition(0, i)
        insertar_datos_en_celda_con_estilo(cel_clients, [camps_factura[i]], negrita_items=[], negrita_forced = True)
    for i in range(len(valors_factura)):
        cel_clients = taula_dades_factura.getCellByPosition(1, i)
        insertar_datos_en_celda_con_estilo(cel_clients, [valors_factura[i]], negrita_items=[], negrita_forced = False)
    for i in range(len(camps_opcionals_factura)):
        cel_clients = taula_dades_factura.getCellByPosition(0, len(camps_factura) + i)
        insertar_datos_en_celda_con_estilo(cel_clients, [camps_opcionals_factura[i]], negrita_items=[], negrita_forced = True)
    for i in range(len(valors_opcionals_factura)):
        cel_clients = taula_dades_factura.getCellByPosition(1, len(camps_factura) + i)
        insertar_datos_en_celda_con_estilo(cel_clients, [valors_opcionals_factura[i]], negrita_items=[], negrita_forced = False)
        
# Insertar una tabla vacía dentro de la celda A5 de la tabla Taula_exterior
if document.TextTables.hasByName("Taula_exterior"):
    taula_exterior = document.TextTables.getByName("Taula_exterior")
    cel_a5 = taula_exterior.getCellByName("A5")
    # Crear una nueva tabla vacía con el número de columnas igual al tamaño de camps_linia_factura y 12 filas
    num_columnas = len(camps_linia_factura)
    num_filas = 2
    taula_productes = document.createInstance("com.sun.star.text.TextTable")
    taula_productes.initialize(num_filas, num_columnas)  # 12 filas, tantas columnas como elementos en camps_linia_factura
    cel_a5.insertTextContent(cel_a5.createTextCursor(), taula_productes, False)
    # Insertar las cabeceras de la tabla (primera fila con los datos de camps_linia_factura en mayúsculas y estilo aplicado)
    for i in range(len(camps_linia_factura)):
        cel_cap = taula_productes.getCellByPosition(i, 0)
        insertar_datos_en_celda_con_estilo(cel_cap, [camps_linia_factura[i]], negrita_items=[], negrita_forced = True)
    # Ajustar los separadores de columna para definir las anchuras relativas
    relsum = taula_productes.TableColumnRelativeSum  # Representa el 100% del ancho total
    # Determinar qué columna es "Descripció"
    index_descripcio = None
    for i in range(num_columnas):
        if taula_productes.getCellByPosition(i, 0).getString() == "Descripció":
            index_descripcio = i
            break
    # Configurar los separadores
    if index_descripcio is not None:
        width_normal = relsum // (num_columnas + 1)  # Asignar espacio a las columnas normales
        width_descripcio = width_normal * 2  # Hacer que la columna de "Descripció" sea el doble de grande
        # Construir la lista de separadores
        separators = taula_productes.TableColumnSeparators
        pos = 0  # Posición acumulativa de cada separador
        for i in range(num_columnas - 1):
            if i == index_descripcio:
                pos += width_descripcio
            else:
                pos += width_normal
            separators[i].Position = pos  # Asignar la posición acumulada
        # Aplicar los nuevos separadores a la tabla
        taula_productes.TableColumnSeparators = separators
        # Configurar los bordes de la tabla
    bordes_tabla = taula_productes.TableBorder2
    empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    bordes_tabla.HorizontalLine = empty_line  # Eliminar líneas horizontales internas
    taula_productes.TableBorder2 = bordes_tabla
    full_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    full_line.OuterLineWidth = bordes_tabla.TopLine.OuterLineWidth  # Usar el mismo grosor del borde superior
    num_columnas = taula_productes.Columns.getCount()
    # Recorrer cada celda de la primera fila para aplicar el borde inferior
    for i in range(num_columnas):
        celda = taula_productes.getCellByPosition(i, 0)  # Celda en la primera fila
        celda.setPropertyValue("BottomBorder", full_line)
    num_filas = taula_productes.Rows.getCount()
    # Definir colores (RGB en decimal)
    color_blanco = 16777215  # Blanco (RGB: 255, 255, 255)
    color_gris = 15132390    # Gris claro (RGB: 230, 230, 230)
    for fila in range(1, num_filas):  # Empieza en 1 para no afectar la cabecera
        color_fila = color_blanco if fila % 2 == 0 else color_gris  # Alternar colores
        for col in range(num_columnas):
            celda = taula_productes.getCellByPosition(col, fila)
            celda.BackColor = color_fila  # Aplicar el color a la celda
    for i in range(len(valors_linia_factura)):
        cel_linia = taula_productes.getCellByPosition(i, 1)
        columna = taula_productes.getCellByPosition(i, 0).getString()
        if columna != 'Descomptes' and columna != 'Impostos' and columna != 'Descripció':
            insertar_datos_en_celda_con_estilo(cel_linia, [valors_linia_factura[i]], negrita_items=[], negrita_forced = False)
        if columna == 'Descripció':
            text_descripcio = valors_linia_factura[i]
            text_descripcio += "\n"
            if len(camps_opcionals_linia_factura) > 0:
                text_descripcio += "- Dades addicionals:\n"
                for d in range(len(camps_opcionals_linia_factura)):
                    text_descripcio += camps_opcionals_linia_factura[d]
                    text_descripcio += ": "
                    text_descripcio += valors_opcionals_linia_factura[d]
                    if (d + 1 != len(camps_opcionals_linia_factura)):
                        text_descripcio += "\n"
            if len(camps_producte) > 0:
                text_descripcio += "- Dades del producte:\n"
                for d in range(len(camps_producte)):
                    text_descripcio += camps_producte[d]
                    text_descripcio += ": "
                    text_descripcio += valors_producte[d]
                    if (d + 1 != len(camps_producte)):
                        text_descripcio += "\n"
            if len(camps_opcionals_producte) > 0:
                text_descripcio += "\n"
                for d in range(len(camps_opcionals_producte)):
                    text_descripcio += camps_opcionals_producte[d]
                    text_descripcio += ": "
                    text_descripcio += valors_opcionals_producte[d]
                    if (d + 1 != len(camps_opcionals_producte)):
                        text_descripcio += "\n"
            insertar_datos_en_celda_con_estilo(cel_linia, [text_descripcio], negrita_items=[], negrita_forced = False) 
        if columna == 'Descomptes':
            text_descomptes = "- " + valors_descomptes[0] + " (" + valors_descomptes[2] + ' % de ' + valors_descomptes[1] + " €) " + valors_descomptes[3] + " €"
            insertar_datos_en_celda_con_estilo(cel_linia, [text_descomptes], negrita_items=[], negrita_forced = False)  
        if columna == 'Impostos':
            text_impostos = "- " + valors_impostos[0] + " (" + valors_impostos[2] + ' % de ' + valors_impostos[1] + " €) " + valors_impostos[3] + " €"
            insertar_datos_en_celda_con_estilo(cel_linia, [text_impostos], negrita_items=[], negrita_forced = False)  

if document.TextTables.hasByName("dades_totals"):
    taula_dades_totals = document.TextTables.getByName("dades_totals")

    # Insertar tantas filas como datos (menos 1 si quieres eliminar el 'Data termini')
    num_filas_actuales = taula_dades_totals.Rows.getCount()
    taula_dades_totals.Rows.insertByIndex(num_filas_actuales, len(camps_pagament_factura) - 2)

    # Eliminar bordes internos, manteniendo solo los exteriores
    bordes_tabla = taula_dades_totals.TableBorder2
    empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    bordes_tabla.HorizontalLine = empty_line
    bordes_tabla.VerticalLine = empty_line
    taula_dades_totals.TableBorder2 = bordes_tabla

    # Insertar datos correctamente
    fila_actual = 0
    for i in range(len(camps_pagament_factura)):
        if camps_pagament_factura[i] != "Data termini":
            # Insertar nombre del campo
            celda_nombre = taula_dades_totals.getCellByPosition(0, fila_actual)
            insertar_datos_en_celda_con_estilo(celda_nombre, [camps_pagament_factura[i]], negrita_items=[], negrita_forced=True)
            
            # Insertar valor del campo
            celda_valor = taula_dades_totals.getCellByPosition(1, fila_actual)
            valor_texto = f"{valors_pagament_factura[i]} €" if isinstance(valors_pagament_factura[i], (int, float, str)) else "-"
            insertar_datos_en_celda_con_estilo(celda_valor, [valor_texto], negrita_items=[], negrita_forced=False)

            # Avanzar fila solo una vez
            fila_actual += 1


if document.TextTables.hasByName("dades_pagament"):
    taula_dades_pagament = document.TextTables.getByName("dades_pagament")
    # Insertar tantas filas como datos personales haya
    num_filas_actuales = taula_dades_pagament.Rows.getCount()
    taula_dades_pagament.Rows.insertByIndex(num_filas_actuales, len(camps_circumstancies) + len(camps_pagaments) - 2)
    # Eliminar bordes internos, manteniendo solo los exteriores
    bordes_tabla = taula_dades_pagament.TableBorder2
    empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    bordes_tabla.HorizontalLine = empty_line  # Eliminar bordes horizontales internos
    bordes_tabla.VerticalLine = empty_line  # Eliminar bordes verticales internos
    taula_dades_pagament.TableBorder2 = bordes_tabla
    insertar_datos_en_celda_con_estilo(taula_dades_pagament.getCellByPosition(0, 0), ["Condicions especials"], negrita_items=[], negrita_forced = True)
    insertar_datos_en_celda_con_estilo(taula_dades_pagament.getCellByPosition(0, 1), ["Pagaments anticipats"], negrita_items=[], negrita_forced = True)
    insertar_datos_en_celda_con_estilo(taula_dades_pagament.getCellByPosition(1, 0), ["- #Descripció_Condició"], negrita_items=[], negrita_forced = False)
    insertar_datos_en_celda_con_estilo(taula_dades_pagament.getCellByPosition(1, 1), ["- " + valors_pagaments[1] + " € al " + valors_pagaments[0]], negrita_items=[], negrita_forced = False)

if document.TextTables.hasByName("dades_mitja_pagament"):
    taula_dades_mitja_pagament = document.TextTables.getByName("dades_mitja_pagament")
    # Insertar tantas filas como datos personales haya
    num_filas_actuales = taula_dades_mitja_pagament.Rows.getCount()
    camps_pagament.insert(3, "Data de venciment")
    valors_pagament.insert(3, "#Data_venciment_Pagament")
    taula_dades_mitja_pagament.Rows.insertByIndex(num_filas_actuales, len(camps_pagament) - 1)
    # Eliminar bordes internos, manteniendo solo los exteriores
    bordes_tabla = taula_dades_mitja_pagament.TableBorder2
    empty_line = uno.createUnoStruct("com.sun.star.table.BorderLine2")
    bordes_tabla.HorizontalLine = empty_line  # Eliminar bordes horizontales internos
    bordes_tabla.VerticalLine = empty_line  # Eliminar bordes verticales internos
    taula_dades_mitja_pagament.TableBorder2 = bordes_tabla
    # Insertar datos en cada fila correctamente
    for i in range(len(camps_pagament)):
        cel_pagament = taula_dades_mitja_pagament.getCellByPosition(0, i)  
        if camps_pagament[i] == "Compte d'abonament":
            insertar_datos_en_celda_con_estilo(cel_pagament, ["IBAN"], negrita_items=[], negrita_forced = True)
        else:
            insertar_datos_en_celda_con_estilo(cel_pagament, [camps_pagament[i]], negrita_items=[], negrita_forced = True)
    for i in range(len(valors_pagament)):
        cel_pagament = taula_dades_mitja_pagament.getCellByPosition(1, i)
        if valors_pagament[i] == "#Compte_d'abonament_Pagament":
            insertar_datos_en_celda_con_estilo(cel_pagament, ["#IBAN_Pagament"], negrita_items=[], negrita_forced = False)
        else:
            insertar_datos_en_celda_con_estilo(cel_pagament, [valors_pagament[i]], negrita_items=[], negrita_forced = False)

# Guardar el documento en formato ODT con opción de sobrescribir
output_path_odt = os.path.join(path_usuari, "plantilla_personal.odt")
output_url_odt = uno.systemPathToFileUrl(output_path_odt)
odt_properties = (
    uno.createUnoStruct("com.sun.star.beans.PropertyValue", Name="Overwrite", Value=True),
)
document.storeAsURL(output_url_odt, odt_properties)

# Guardar el documento en formato PDF con opción de sobrescribir
output_path_pdf = os.path.join(path_usuari, "plantilla_personal.pdf")
output_url_pdf = uno.systemPathToFileUrl(output_path_pdf)
pdf_properties = (
    uno.createUnoStruct("com.sun.star.beans.PropertyValue", Name="FilterName", Value="writer_pdf_Export"),
    uno.createUnoStruct("com.sun.star.beans.PropertyValue", Name="Overwrite", Value=True),
)
document.storeToURL(output_url_pdf, pdf_properties)

# Cerrar el documento
document.close(True)