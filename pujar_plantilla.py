import uno
import os
import sys
import json
import re

allData = json.load(sys.stdin)

valors_personals = allData['valors_personals']
valors_clients = allData['valors_clients']
valors_factura = allData['valors_factura']
valors_linia_factura = allData['valors_linia_factura']
valors_descomptes = allData['valors_descomptes']
valors_impostos = allData['valors_impostos']

valors_pagament_factura = allData['valors_pagament_factura']
valors_circumstancies = allData['valors_circumstancies']
valors_pagaments = allData['valors_pagaments']
valors_pagament = allData['valors_pagament'] 

path_usuari = allData['user_path']

valors_linia_factura += ['#Subtotal_Linia', '#Total_Linia']
valors_descomptes += ['#Total_Descompte_Linia']
valors_impostos += ['#Total_Impost_Linia']

valors_pagament += ['#Total_a_pagar_Pagament']

# Reemplazos deseados
reemplazos = {
    "#Descripció_Circumstancia": "#Descripció_Condició",
    "#Compte_d'abonament_Pagament": "#IBAN_Pagament",
    "#Data_termini_Pagament": "#Data_venciment_Pagament"
}

# Aplicar los reemplazos a cada lista de placeholders
placeholders = (
    valors_personals +
    valors_clients +
    valors_factura +
    valors_linia_factura +
    valors_descomptes +
    valors_impostos +
    valors_pagament_factura +
    valors_circumstancies +
    valors_pagaments +
    valors_pagament
)

# Aplicar reemplazos
placeholders = [
    reemplazos.get(ph, ph) for ph in placeholders
]

plantilla_tmp_path = os.path.join(path_usuari, "plantilla_personal_tmp.odt")

def obtener_texto_documento(document):
    """ Obtiene todas las palabras individuales del documento excluyendo tablas. """
    texto_completo = document.Text.getString()
    palabras = re.findall(r'\b\w+\b', texto_completo)
    return " ".join(palabras)

def obtener_texto_tablas(document):
    """ Obtiene el texto de todas las tablas en el documento, omitiendo tablas anidadas y celdas inválidas. """
    texto = []
    celdas_procesadas = set()
    for tabla in document.TextTables:
        for fila in range(tabla.Rows.Count):
            for columna in range(tabla.Columns.Count):
                try:
                    if fila >= tabla.Rows.Count or columna >= tabla.Columns.Count:
                        continue
                    celda = tabla.getCellByPosition(columna, fila)
                    # Verificar si la celda contiene una tabla anidada
                    if celda.supportsService("com.sun.star.text.TextTable"):
                        continue
                    # Usar enumeración para detectar estructuras internas antes de leer el texto
                    if hasattr(celda, "Text"):
                        enumeration = celda.Text.createEnumeration()
                        while enumeration.hasMoreElements():
                            element = enumeration.nextElement()
                            if element.supportsService("com.sun.star.text.TextTable"):
                                break
                        else:
                            celda_texto = celda.getString().strip()
                            if celda_texto and celda_texto not in celdas_procesadas:
                                texto.append(celda_texto)
                                celdas_procesadas.add(celda_texto)
                except Exception:
                    continue  # Omitir celdas con errores
    return " ".join(texto)

def obtener_palabras(document):
    """ Extrae todas las palabras del documento, incluyendo las de las tablas. """
    texto_fuera_tablas = obtener_texto_documento(document)
    texto_tablas = obtener_texto_tablas(document)
    texto_completo = texto_fuera_tablas + " " + texto_tablas
    palabras = re.findall(r'#\S+', texto_completo)  # Buscar palabras que empiezan con #
    return palabras

def main():
    file_url = uno.systemPathToFileUrl(plantilla_tmp_path)
    # Conectar con LibreOffice
    local_context = uno.getComponentContext()
    resolver = local_context.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local_context)
    ctx = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext")
    smgr = ctx.ServiceManager
    desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
    # Cargar el documento
    document = desktop.loadComponentFromURL(file_url, "_blank", 0, ())
    # Obtener y mostrar palabras
    palabras = obtener_palabras(document)
    # Convertir las listas de placeholders y palabras a conjuntos para comparación
    placeholders_set = set(placeholders)
    palabras_set = set(palabras)
    placeholders_faltantes = list(placeholders_set - palabras_set)
    # Devolver resultado en JSON
    resultado = {"placeholders_faltantes": placeholders_faltantes}
    if placeholders_faltantes:
        # Cerrar el documento sin guardar
        document.close(True)
        print(json.dumps(resultado, ensure_ascii=False))
        sys.exit(1)  # Indicar error si hay placeholders faltantes
    else:
        # Guardar el documento en formato PDF con opción de sobrescribir
        output_path_pdf = os.path.join(path_usuari, "plantilla_personal_tmp.pdf")
        output_url_pdf = uno.systemPathToFileUrl(output_path_pdf)
        pdf_properties = (
            uno.createUnoStruct("com.sun.star.beans.PropertyValue", Name="FilterName", Value="writer_pdf_Export"),
            uno.createUnoStruct("com.sun.star.beans.PropertyValue", Name="Overwrite", Value=True),
        )
        document.storeToURL(output_url_pdf, pdf_properties)
        # Cerrar el documento
        document.close(True)
        print(json.dumps({"message": "Todos los placeholders están presentes"}))
        sys.exit(0)  # Indicar éxito si no faltan placeholders
    # print(json.dumps(palabras, ensure_ascii=False, indent=2))
    # print(f"Placeholders: {len(placeholders)}")
    # print(f"placeholders: {placeholders}")

if __name__ == "__main__":
    main()