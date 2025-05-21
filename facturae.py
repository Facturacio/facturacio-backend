import os
import sys
import json
import re
from collections import defaultdict
from pprint import pprint
from datetime import datetime

def convertir_a_iso8601(fecha_str: str) -> str:
    try:
        # Parsear la fecha en formato día/mes/año
        fecha = datetime.strptime(fecha_str, "%d/%m/%Y")
        # Convertir a formato ISO 8601 (YYYY-MM-DD)
        return fecha.date().isoformat()
    except ValueError:
        # Manejar errores (opcional)
        return fecha_str  # o lanzar una excepción

def main():
    try:
        allData = json.load(sys.stdin)

        placeholders_personals = allData['placeholders_personals']
        valors_personals = allData['valors_personals']
        placeholders_clients = allData['placeholders_clients']
        valors_clients = allData['valors_clients']
        placeholders_factura = allData['placeholders_factura']
        valors_factura = allData['valors_factura']
        placeholders_linia_factura = allData['placeholders_linia_factura']
        valors_linia_factura = allData['valors_linia_factura']
        placeholders_subtotal_linia_factura = allData['placeholders_subtotal_linia_factura']
        valors_subtotal_linia_factura = allData['valors_subtotal_linia_factura']
        placeholders_total_linia_factura = allData['placeholders_total_linia_factura']
        valors_total_linia_factura = allData['valors_total_linia_factura']
        placeholders_producte = allData['placeholders_producte']
        valors_producte = allData['valors_producte']
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
        serie = allData['serie']

        #Eliminar '#Mitjà_de_pagament_Pagament' de placeholders_pagament_factura y su dato asociado
        if '#Mitjà_de_pagament_Pagament' in placeholders_pagament_factura:
            index_to_remove = placeholders_pagament_factura.index('#Mitjà_de_pagament_Pagament')
            placeholders_pagament_factura.pop(index_to_remove)
            dades_pagament_factura.pop(index_to_remove)

        placeholders_linia_factura += ['#Unitats_Linia']
        for i, fila in enumerate(valors_linia_factura):
            index_unitats = placeholders_producte.index('#Unitats_Producte')
            valors_linia_factura[i] += [valors_producte[i][index_unitats]]

        # Contenido que se usará para sustituir #remitent
        dades_personals = '''<TaxIdentification>
                <PersonTypeCode>#Tipus_de_persona_Personal</PersonTypeCode>
                <ResidenceTypeCode>#Tipus_de_residència_Personal</ResidenceTypeCode>
                <TaxIdentificationNumber>#Número_d'identificació_fiscal_Personal</TaxIdentificationNumber>
            </TaxIdentification>
            <Individual>
                <Name>#Nom_Personal</Name>
                <FirstSurname>#Primer_cognom_Personal</FirstSurname>
                #address
            </Individual>'''
        # Contenido que se usará para sustituir #remitent
        dades_personals_juridic = '''<TaxIdentification>
                <PersonTypeCode>#Tipus_de_persona_Personal</PersonTypeCode>
                <ResidenceTypeCode>#Tipus_de_residència_Personal</ResidenceTypeCode>
                <TaxIdentificationNumber>#Número_d'identificació_fiscal_Personal</TaxIdentificationNumber>
            </TaxIdentification>
            #codis_centre
            <LegalEntity>
                <CorporateName>#Nom_i_cognoms_o_raó_social_Personal</CorporateName>
                #address
            </LegalEntity>'''
        # Contenido que se usará para sustituir #remitent
        dades_client = '''<TaxIdentification>
                <PersonTypeCode>#Tipus_de_persona_Client</PersonTypeCode>
                <ResidenceTypeCode>#Tipus_de_residència_Client</ResidenceTypeCode>
                <TaxIdentificationNumber>#Número_d'identificació_fiscal_Client</TaxIdentificationNumber>
            </TaxIdentification>
            <Individual>
                <Name>#Nom_Client</Name>
                <FirstSurname>#Primer_cognom_Client</FirstSurname>
                #address
            </Individual>'''
        # Contenido que se usará para sustituir #remitent
        dades_client_juridic = '''<TaxIdentification>
                <PersonTypeCode>#Tipus_de_persona_Client</PersonTypeCode>
                <ResidenceTypeCode>#Tipus_de_residència_Client</ResidenceTypeCode>
                <TaxIdentificationNumber>#Número_d'identificació_fiscal_Client</TaxIdentificationNumber>
            </TaxIdentification>
            #codis_centre
            <LegalEntity>
                <CorporateName>#Nom_i_cognoms_o_raó_social_Client</CorporateName>
                #address
            </LegalEntity>'''
        address_spain_client = '''<AddressInSpain>
                    <Address>#Direcció_Client</Address>
                    <PostCode>#Codi_Postal_Client</PostCode>
                    <Town>#Població_Client</Town>
                    <Province>#Província_Client</Province>
                    <CountryCode>#País_Client</CountryCode>
                </AddressInSpain>'''
        address_spain_personal = '''<AddressInSpain>
                    <Address>#Direcció_Personal</Address>
                    <PostCode>#Codi_Postal_Personal</PostCode>
                    <Town>#Població_Personal</Town>
                    <Province>#Província_Personal</Province>
                    <CountryCode>#País_Personal</CountryCode>
                </AddressInSpain>'''
        address_overseas_client = '''<OverseasAddress>
                    <Address>#Direcció_Client</Address>
                    <PostCodeAndTown>#Codi_Postal_Client #Població_Client</PostCodeAndTown>
                    <Province>#Província_Client</Province>
                    <CountryCode>#País_Client</CountryCode>
                </OverseasAddress>'''
        address_overseas_personal = '''<OverseasAddress>
                    <Address>#Direcció_Personal</Address>
                    <PostCodeAndTown>#Codi_Postal_Personal #Població_Personal</PostCodeAndTown>
                    <Province>#Província_Personal</Province>
                    <CountryCode>#País_Personal</CountryCode>
                </OverseasAddress>'''
        address_spain_centro = '''<AddressInSpain>
                        <Address>#Direcció_Client</Address>
                        <PostCode>#Codi_Postal_Client</PostCode>
                        <Town>#Població_Client</Town>
                        <Province>#Província_Client</Province>
                        <CountryCode>#País_Client</CountryCode>
                    </AddressInSpain>'''
        address_overseas_centro = '''<OverseasAddress>
                        <Address>#Direcció_Client</Address>
                        <PostCodeAndTown>#Codi_Postal_Client #Població_Client</PostCodeAndTown>
                        <Province>#Província_Client</Province>
                        <CountryCode>#País_Client</CountryCode>
                    </OverseasAddress>'''
        dades_impost = '''                 <Tax>
                    <TaxTypeCode>#impost_Impost_Linia</TaxTypeCode>
                    <TaxRate>#Tipus_impositiu_Impost_Linia</TaxRate>
                    <TaxableBase>
                        <TotalAmount>#Base_imposable_Impost_Linia</TotalAmount>
                    </TaxableBase>
                    <TaxAmount>
                        <TotalAmount>#Total_Impost_Linia</TotalAmount>
                    </TaxAmount>
                </Tax>
'''
        dades_linies = '''                <InvoiceLine>
                    <ItemDescription>#Descripció_Linia</ItemDescription>
                    <Quantity>#Quantitat_Linia</Quantity>
                    <UnitOfMeasure>#Unitats_Linia</UnitOfMeasure>
                    <UnitPriceWithoutTax>#Preu_unitari_Linia</UnitPriceWithoutTax>
                    <TotalCost>#Preu_linia</TotalCost>
                    #descomptes_linia
                    <GrossAmount>#preu_descomptes</GrossAmount>
                    #impostos_linia
                </InvoiceLine>
'''
        dades_impost_linia = '''                        <Tax>
                            <TaxTypeCode>#impost_Impost_Linia</TaxTypeCode>
                            <TaxRate>#Tipus_impositiu_Impost_Linia</TaxRate>
                            <TaxableBase>
                                <TotalAmount>#Base_imposable_Impost_Linia</TotalAmount>
                            </TaxableBase>
                            <TaxAmount>
                                <TotalAmount>#Total_Impost_Linia</TotalAmount>
                            </TaxAmount>
                        </Tax>
'''
        def codi_unitat(nom: str) -> str:
            codis = {
                'Unitats': '01',
                'Hores': '02',
                'Quilograms': '03',
                'Litres': '04',
                'Altres': '05',
                'Caixes': '06',
                'Safates': '07',
                'Barrils': '08',
                'Bidons': '09',
                'Bosses': '10',
                'Bombones': '11',
                'Ampolles': '12',
                'Pots': '13',
                'Tetrabrics': '14',
                'Centilitres': '15',
                'Centímetres': '16',
                'Cubells': '17',
                'Dotzenes': '18',
                'Estoigs': '19',
                'Garrafes': '20',
                'Grams': '21',
                'Quilòmetres': '22',
                'Llaunes': '23',
                'Manats': '24',
                'Metres': '25',
                'Mil·límetres': '26',
                'Paquets de 6': '27',
                'Paquets': '28',
                'Racions': '29',
                'Rotllos': '30',
                'Sobres': '31',
                'Terrines': '32',
                'Metres cúbics': '33',
                'Segons': '34',
                'Watts': '35'
            }
            return codis.get(nom, nom)

        def traduir_metode_pagament(mitja_pagament: str) -> str:
            traduccions = {
                'Al comptat': '01',
                'Rebut domiciliat': '02',
                'Rebut': '03',
                'Transferència': '04',
                'Lletra acceptada': '05',
                'Crèdit documentari': '06',
                'Contracte d’adjudicació': '07',
                'Lletra de canvi': '08',
                'Pagaré a l’ordre': '09',
                'Pagaré no a l’ordre': '10',
                'Xec': '11',
                'Reposició': '12',
                'Especials': '13',
                'Compensació': '14',
                'Gir postal': '15',
                'Xec conformat': '16',
                'Xec bancari': '17',
                'Pagament contra reemborsament': '18',
                'Pagament mitjançant targeta': '19'
            }
            return traduccions.get(mitja_pagament, mitja_pagament)  # Retorna el valor original si no se encuentra

        def traduir_tipus_persona(tipus_persona: str) -> str:
            traduccions = {
                'Física': 'F',
                'Jurídica': 'J'
            }
            return traduccions.get(tipus_persona, tipus_persona)  # Retorna el valor original si no se encuentra

        def traduir_tipus_residencia(tipus_residencia: str) -> str:
            traduccions = {
                'Resident': 'R',
                'No resident UE': 'E',
                'Resident UE': 'U'
            }
            return traduccions.get(tipus_residencia, tipus_residencia)  # Retorna el valor original si no se encuentra

        def codi_tipus_impost(nom: str) -> str:
            codis = {
                'IVA': '01', 
                'IPSI': '02', 
                'IGIC': '03', 
                'IRPF': '04', 
                'ALTRES': '05',
                'ITPAJD': '06', 
                'IE': '07', 
                'RA': '08', 
                'IGTECM': '09', 
                'ECDPCAC': '10',
                'IIIMAB': '11', 
                'ICIO': '12', 
                'IMVDN': '13', 
                'IMSN': '14', 
                'IMGSN': '15',
                'IMPN': '16', 
                'REIVA': '17', 
                'REIGIC': '18', 
                'REIPSI': '19', 
                'IPS': '20',
                'RLEA': '21', 
                'IVPEE': '22', 
                'INR': '23', 
                'IAF': '24', 
                'IDEC': '25',
                'ITC': '26', 
                'IGFEI': '27', 
                'IRNR': '28', 
                'IS': '29'
            }
            return codis.get(nom, nom)

        def traduir_pais_a_iso_alpha3(pais: str) -> str:
            traduccions = {
                'Afganistan': 'AFG',
                'Albània': 'ALB',
                'Alemanya': 'DEU',
                'Algèria': 'DZA',
                'Samoa Nord-americana': 'ASM',
                'Andorra': 'AND',
                'Angola': 'AGO',
                'Anguilla': 'AIA',
                'Antàrtida': 'ATA',
                'Antigua i Barbuda': 'ATG',
                'Argentina': 'ARG',
                'Armènia': 'ARM',
                'Aruba': 'ABW',
                'Austràlia': 'AUS',
                'Azerbaidjan': 'AZE',
                'Bahames': 'BHS',
                'Bahrain': 'BHR',
                'Bangladesh': 'BGD',
                'Barbados': 'BRB',
                'Belarús': 'BLR',
                'Belize': 'BLZ',
                'Benín': 'BEN',
                'Bermudes': 'BMU',
                'Bhutan': 'BTN',
                'Bolívia': 'BOL',
                'Bonaire, Sint Eustatius i Saba': 'BES',
                'Bòsnia i Hercegovina': 'BIH',
                'Botswana': 'BWA',
                'Illa Bouvet': 'BVT',
                'Brasil': 'BRA',
                'Territori Britànic de l\'Oceà Índic': 'IOT',
                'Brunei': 'BRN',
                'Bulgària': 'BGR',
                'Burkina Faso': 'BFA',
                'Burundi': 'BDI',
                'Bèlgica': 'BEL',
                'Cap Verd': 'CPV',
                'Cambodja': 'KHM',
                'Camerun': 'CMR',
                'Canadà': 'CAN',
                'Illes Caiman': 'CYM',
                'República Centreafricana': 'CAF',
                'Txad': 'TCD',
                'Xile': 'CHL',
                'Illa Christmas': 'CXR',
                'Illes Cocos': 'CCK',
                'Colòmbia': 'COL',
                'Comores': 'COM',
                'Congo': 'COG',
                'República Democràtica del Congo': 'COD',
                'Illes Cook': 'COK',
                'Costa Rica': 'CRI',
                'Croàcia': 'HRV',
                'Cuba': 'CUB',
                'Curaçao': 'CUW',
                'Costa d\'Ivori': 'CIV',
                'Dinamarca': 'DNK',
                'Djibouti': 'DJI',
                'Dominica': 'DMA',
                'República Dominicana': 'DOM',
                'Equador': 'ECU',
                'Egipte': 'EGY',
                'El Salvador': 'SLV',
                'Guinea Equatorial': 'GNQ',
                'Eritrea': 'ERI',
                'Eslovàquia': 'SVK',
                'Eslovènia': 'SVN',
                'Espanya': 'ESP',
                'Estats Units': 'USA',
                'Estònia': 'EST',
                'Eswatini': 'SWZ',
                'Etiòpia': 'ETH',
                'Illes Malvines': 'FLK',
                'Illes Fèroe': 'FRO',
                'Fiji': 'FJI',
                'Finlàndia': 'FIN',
                'França': 'FRA',
                'Guaiana Francesa': 'GUF',
                'Polinèsia Francesa': 'PYF',
                'Territoris Australs Francesos': 'ATF',
                'Gabon': 'GAB',
                'Gàmbia': 'GMB',
                'Geòrgia': 'GEO',
                'Ghana': 'GHA',
                'Gibraltar': 'GIB',
                'Grenlàndia': 'GRL',
                'Granada': 'GRD',
                'Grècia': 'GRC',
                'Guadeloupe': 'GLP',
                'Guam': 'GUM',
                'Guatemala': 'GTM',
                'Guernsey': 'GGY',
                'Guinea': 'GIN',
                'Guinea Bissau': 'GNB',
                'Guyana': 'GUY',
                'Haití': 'HTI',
                'Illa Heard i Illes McDonald': 'HMD',
                'Santa Seu (Vaticà)': 'VAT',
                'Hondures': 'HND',
                'Hong Kong': 'HKG',
                'Hongria': 'HUN',
                'Indonèsia': 'IDN',
                'Iran': 'IRN',
                'Iraq': 'IRQ',
                'Irlanda': 'IRL',
                'Illa de Man': 'IMN',
                'Islàndia': 'ISL',
                'Israel': 'ISR',
                'Itàlia': 'ITA',
                'Jamaica': 'JAM',
                'Japó': 'JPN',
                'Jersey': 'JEY',
                'Jordània': 'JOR',
                'Kazakhstan': 'KAZ',
                'Kenya': 'KEN',
                'Kiribati': 'KIR',
                'Corea del Nord': 'PRK',
                'Corea del Sud': 'KOR',
                'Kuwait': 'KWT',
                'Kirguizstan': 'KGZ',
                'Laos': 'LAO',
                'Líban': 'LBN',
                'Lesotho': 'LSO',
                'Letònia': 'LVA',
                'Libèria': 'LBR',
                'Líbia': 'LBY',
                'Liechtenstein': 'LIE',
                'Lituània': 'LTU',
                'Luxemburg': 'LUX',
                'Macau': 'MAC',
                'Madagascar': 'MDG',
                'Malawi': 'MWI',
                'Malàisia': 'MYS',
                'Maldives': 'MDV',
                'Mali': 'MLI',
                'Malta': 'MLT',
                'Illes Marshall': 'MHL',
                'Martinica': 'MTQ',
                'Mauritània': 'MRT',
                'Maurici': 'MUS',
                'Mayotte': 'MYT',
                'Micronèsia': 'FSM',
                'Moldàvia': 'MDA',
                'Mònaco': 'MCO',
                'Mongòlia': 'MNG',
                'Montenegro': 'MNE',
                'Montserrat': 'MSR',
                'Marroc': 'MAR',
                'Moçambic': 'MOZ',
                'Myanmar': 'MMR',
                'Mèxic': 'MEX',
                'Namíbia': 'NAM',
                'Nauru': 'NRU',
                'Nepal': 'NPL',
                'Nova Caledònia': 'NCL',
                'Nicaragua': 'NIC',
                'Níger': 'NER',
                'Nigèria': 'NGA',
                'Niue': 'NIU',
                'Illa Norfolk': 'NFK',
                'Macedònia del Nord': 'MKD',
                'Illes Mariannes del Nord': 'MNP',
                'Noruega': 'NOR',
                'Nova Zelanda': 'NZL',
                'Oman': 'OMN',
                'Pakistan': 'PAK',
                'Palau': 'PLW',
                'Palestina': 'PSE',
                'Panamà': 'PAN',
                'Papua Nova Guinea': 'PNG',
                'Paraguai': 'PRY',
                'Països Baixos': 'NLD',
                'Perú': 'PER',
                'Filipines': 'PHL',
                'Illes Pitcairn': 'PCN',
                'Polònia': 'POL',
                'Portugal': 'PRT',
                'Puerto Rico': 'PRI',
                'Qatar': 'QAT',
                'Regne Unit': 'GBR',
                'Romania': 'ROU',
                'Federació Russa': 'RUS',
                'Ruanda': 'RWA',
                'Reunió': 'REU',
                'Saint-Barthélemy': 'BLM',
                'Saint Helena, Ascensió i Tristan da Cunha': 'SHN',
                'Saint Kitts i Nevis': 'KNA',
                'Saint Lucia': 'LCA',
                'Saint Martin (part francesa)': 'MAF',
                'Saint-Pierre i Miquelon': 'SPM',
                'Saint Vincent i les Grenadines': 'VCT',
                'Samoa': 'WSM',
                'San Marino': 'SMR',
                'São Tomé i Príncipe': 'STP',
                'Aràbia Saudita': 'SAU',
                'Senegal': 'SEN',
                'Sèrbia': 'SRB',
                'Seychelles': 'SYC',
                'Sierra Leone': 'SLE',
                'Singapur': 'SGP',
                'Sint Maarten (part neerlandesa)': 'SXM',
                'Illes Salomó': 'SLB',
                'Somàlia': 'SOM',
                'Geòrgia del Sud i les Illes Sandwich del Sud': 'SGS',
                'Sudan del Sud': 'SSD',
                'Sri Lanka': 'LKA',
                'Sud-àfrica': 'ZAF',
                'Sudan': 'SDN',
                'Surinam': 'SUR',
                'Suècia': 'SWE',
                'Suïssa': 'CHE',
                'Svalbard i Jan Mayen': 'SJM',
                'Síria': 'SYR',
                'Taiwan': 'TWN',
                'Tadjikistan': 'TJK',
                'Tanzània': 'TZA',
                'Tailàndia': 'THA',
                'Timor Oriental': 'TLS',
                'Togo': 'TGO',
                'Tokelau': 'TKL',
                'Tonga': 'TON',
                'Trinidad i Tobago': 'TTO',
                'Tunísia': 'TUN',
                'Turkmenistan': 'TKM',
                'Illes Turks i Caicos': 'TCA',
                'Turquia': 'TUR',
                'Tuvalu': 'TUV',
                'Txèquia': 'CZE',
                'Uganda': 'UGA',
                'Ucraïna': 'UKR',
                'Emirats Àrabs Units': 'ARE',
                'Illes Perifèriques Menors dels EUA': 'UMI',
                'Uruguai': 'URY',
                'Uzbekistan': 'UZB',
                'Vanuatu': 'VUT',
                'Veneçuela': 'VEN',
                'Vietnam': 'VNM',
                'Illes Verges Britàniques': 'VGB',
                'Illes Verges Nord-americanes': 'VIR',
                'Wallis i Futuna': 'WLF',
                'Sàhara Occidental': 'ESH',
                'Xina': 'CHN',
                'Xipre': 'CYP',
                'Iemen': 'YEM',
                'Zàmbia': 'ZMB',
                'Zimbàbue': 'ZWE',
                'Àustria': 'AUT',
                'Illes Åland': 'ALA',
                'Índia': 'IND'
            }
            return traduccions.get(pais, pais)  # Retorna el valor original si no se encuentra

        # Lista final de impuestos agrupados
        impostos_agregats = defaultdict(lambda: {
            '#Base_imposable_Impost_Linia': 0,
            '#Total_Impost_Linia': 0
        })

        sum_impostos = 0
        for grup in valors_impostos:
            for entrada in grup:
                if len(entrada) < 2:
                    continue  # Salta si no hay al menos nombre y base
                nom = entrada[0]
                codi = codi_tipus_impost(nom)
                base_str = entrada[1]
                tipus = entrada[2] if len(entrada) > 2 and entrada[2] not in (None, '', 'null') else "100"
                total_str = entrada[3] if len(entrada) > 3 and entrada[3] not in (None, '', 'null') else base_str
                try:
                    base = float(base_str)
                    total = float(total_str)
                    sum_impostos += total
                except ValueError:
                    continue  # Salta si base o total no son números
                key = (codi, tipus)
                impostos_agregats[key]['#impost_Impost_Linia'] = codi
                impostos_agregats[key]['#Tipus_impositiu_Impost_Linia'] = tipus
                impostos_agregats[key]['#Base_imposable_Impost_Linia'] += base
                impostos_agregats[key]['#Total_Impost_Linia'] += total
        # Convertimos a lista de diccionarios
        resultado = list(impostos_agregats.values())

        placeholders_pagament_factura.append('#Total_Imposts')
        dades_pagament_factura.append(str(sum_impostos))

        sum_pagaments_anticipats = 0
        text_final_anticipats = ""

        if len(dades_pagaments) > 0:
            text_final_anticipats = '''<PaymentsOnAccount>
'''
            for pagament in dades_pagaments:
                if len(entrada) < 2:
                    continue  # Salta si no hay al menos nombre y base
                data_pagament = pagament[0]
                import_pagament = pagament[1]
                try:
                    data_pagament = convertir_a_iso8601(data_pagament)
                    import_pagament_valor = float(import_pagament)
                    sum_pagaments_anticipats += import_pagament_valor
                except ValueError:
                    continue  # Salta si base o total no son números
                text_desc = '''                    <PaymentOnAccount>
                        <PaymentOnAccountDate>''' + data_pagament + '''</PaymentOnAccountDate>
                        <PaymentOnAccountAmount>''' + import_pagament + '''</PaymentOnAccountAmount>
                    </PaymentOnAccount>'''
                text_final_anticipats += text_desc
            text_final_anticipats += '''
                </PaymentsOnAccount>'''

        placeholders_pagament_factura.append('#Total_Imposts')
        dades_pagament_factura.append(str(sum_impostos))

        # Combinamos todos los diccionarios en uno solo
        placeholders_dict = {
            **dict(zip(placeholders_personals, valors_personals)),
            **dict(zip(placeholders_clients, valors_clients)),
            **dict(zip(placeholders_factura, valors_factura)),
            **dict(zip(placeholders_pagament_factura, dades_pagament_factura)),
            **dict(zip(placeholders_pagament, dades_pagament))
        }

        placeholders_dict['#Sèrie_Factura'] = serie + "-"
        valor_total = f"{float(placeholders_dict['#Total_Pagament']):.2f}"
        valor_total_anticipat = f"{float(sum_pagaments_anticipats):.2f}"
        valor_total_factura = str(f"{float(valor_total) - float(valor_total_anticipat):.2f}")        
        placeholders_dict['#Total_realitzar'] = valor_total_factura

        if placeholders_dict['#Tipus_de_persona_Personal'] == 'Física':
            nom_complet_personal = placeholders_dict['#Nom_i_cognoms_o_raó_social_Personal']
            try:
                nom_parts = [part.strip() for part in nom_complet_personal.split(',')]
                if len(nom_parts) >= 2:
                    nom = nom_parts[0]
                    cognom = nom_parts[1]
                else:
                    nom = nom_parts[0]
                    cognom = ""
            except Exception:
                nom = ""
                cognom = ""
            placeholders_dict['#Nom_Personal'] = nom
            placeholders_dict['#Primer_cognom_Personal'] = cognom
        placeholders_dict['#Tipus_de_persona_Personal'] = traduir_tipus_persona(placeholders_dict['#Tipus_de_persona_Personal'])
        placeholders_dict['#Tipus_de_residència_Personal'] = traduir_tipus_residencia(placeholders_dict['#Tipus_de_residència_Personal'])
        placeholders_dict['#País_Personal'] = traduir_pais_a_iso_alpha3(placeholders_dict['#País_Personal'])

        if placeholders_dict['#Tipus_de_persona_Client'] == 'Física':
            nom_complet_client = placeholders_dict['#Nom_i_cognoms_o_raó_social_Client']
            try:
                nom_parts = [part.strip() for part in nom_complet_client.split(',')]
                if len(nom_parts) >= 2:
                    nom = nom_parts[0]
                    cognom = nom_parts[1]
                else:
                    nom = nom_parts[0]
                    cognom = ""
            except Exception:
                nom = ""
                cognom = ""
            placeholders_dict['#Nom_Client'] = nom
            placeholders_dict['#Primer_cognom_Client'] = cognom
        placeholders_dict['#Tipus_de_persona_Client'] = traduir_tipus_persona(placeholders_dict['#Tipus_de_persona_Client'])
        placeholders_dict['#Tipus_de_residència_Client'] = traduir_tipus_residencia(placeholders_dict['#Tipus_de_residència_Client'])
        placeholders_dict['#País_Client'] = traduir_pais_a_iso_alpha3(placeholders_dict['#País_Client'])

        # Expresión regular para encontrar placeholders
        patron = r"#([\w']+)"

        # Leer el archivo XML
        with open(os.path.join("plantilla_electronica.xml"), "r", encoding="utf-8") as f:
            contenido = f.read()

        # Buscar y reemplazar placeholders
        resultados = re.findall(patron, contenido, re.UNICODE)

        #print("Palabras encontradas y reemplazadas:")
        for palabra in set(resultados):  # Evita repeticiones
            placeholder = f"#{palabra}"
            if placeholder in placeholders_dict:
                valor = placeholders_dict[placeholder]
                if placeholder == "#Data_Factura":
                    # Formatear la fecha
                    valor = convertir_a_iso8601(valor)
                if placeholder == "#Data_termini_Pagament":
                    # Formatear la fecha
                    valor = convertir_a_iso8601(valor)
                if placeholder == "#Mitjà_de_pagament_Pagament":
                    # Formatear la fecha
                    codi_mitja = traduir_metode_pagament(valor)
                    valor = '''<PaymentMeans>''' + codi_mitja + '''</PaymentMeans>'''
                    if codi_mitja == '04':
                        # Si el método de pago es transferencia, agregar el bloque adicional
                        valor += '''
                            <AccountToBeCredited>
                                <IBAN>''' + placeholders_dict["#Compte_d'abonament_Pagament"] +  '''</IBAN>
                            </AccountToBeCredited>'''
                    elif codi_mitja == '02':
                        # Si el método de pago es rebut domiciliat, agregar el bloque adicional
                        valor += '''
                            <AccountToBeDebited>
                                <IBAN>''' + placeholders_dict["#Compte_d'abonament_Pagament"] +  '''</IBAN>
                            </AccountToBeDebited>'''
                if placeholder == "#Total_Pagament":
                    # Formatear a 2 decimales
                    valor = f"{float(valor):.2f}"
                contenido = contenido.replace(placeholder, valor)
                #print(f"{placeholder} => {valor}")
            elif placeholder == "#dades_personals":
                # Reemplazar los placeholders dentro del contenido de dades_personals
                if placeholders_dict["#Tipus_de_persona_Personal"] == "J":
                    if placeholders_dict["#País_Personal"] == "ESP":
                        dades_personals_juridic = dades_personals_juridic.replace("#address", address_spain_personal)
                    else:
                        dades_personals_juridic = dades_personals_juridic.replace("#address", address_overseas_personal)
                    for sub_placeholder, sub_valor in placeholders_dict.items():
                        dades_personals_juridic = dades_personals_juridic.replace(sub_placeholder, sub_valor)
                    contenido = contenido.replace(placeholder, dades_personals_juridic)
                else:
                    if placeholders_dict["#País_Personal"] == "ESP":
                        dades_personals = dades_personals.replace("#address", address_spain_personal)
                    else:
                        dades_personals = dades_personals.replace("#address", address_overseas_personal)
                    for sub_placeholder, sub_valor in placeholders_dict.items():
                        dades_personals = dades_personals.replace(sub_placeholder, sub_valor)
                    contenido = contenido.replace(placeholder, dades_personals)
            elif placeholder == "#dades_client":
                # Reemplazar los placeholders dentro del contenido de dades_client
                if placeholders_dict["#Tipus_de_persona_Client"] == "J":
                    if placeholders_dict["#Codi_de_l'òrgan_gestor_Client"] != "" and placeholders_dict["#Codi_de_la_unitat_tramitadora_Client"] != "" and placeholders_dict["#Codi_de_l'oficina_comptable_Client"] != "":
                        text_centros = '''<AdministrativeCentres>
            '''
                        if placeholders_dict["#Codi_de_l'òrgan_gestor_Client"] != "":
                            text_centros += '''    <AdministrativeCentre>
                    <CentreCode>#Codi_de_l'òrgan_gestor_Client</CentreCode>
                    <RoleTypeCode>02</RoleTypeCode>
                    <Name>#Nom_i_cognoms_o_raó_social_Client</Name>
                    #addcentro
                </AdministrativeCentre>
            '''
                        if placeholders_dict["#Codi_de_la_unitat_tramitadora_Client"] != "":
                            text_centros += '''    <AdministrativeCentre>
                    <CentreCode>#Codi_de_la_unitat_tramitadora_Client</CentreCode>
                    <RoleTypeCode>03</RoleTypeCode>
                    <Name>#Nom_i_cognoms_o_raó_social_Client</Name>
                    #addcentro
                </AdministrativeCentre>
            '''
                        if placeholders_dict["#Codi_de_l'oficina_comptable_Client"] != "":
                            text_centros += '''    <AdministrativeCentre>
                    <CentreCode>#Codi_de_l'oficina_comptable_Client</CentreCode>
                    <RoleTypeCode>01</RoleTypeCode>
                    <Name>#Nom_i_cognoms_o_raó_social_Client</Name>
                    #addcentro
                </AdministrativeCentre>
            '''
                        text_centros += '''</AdministrativeCentres>'''
                        dades_client_juridic = dades_client_juridic.replace("#codis_centre", text_centros)
                        for sub_placeholder, sub_valor in placeholders_dict.items():
                            text_centros = text_centros.replace(sub_placeholder, sub_valor)
                    else:
                        dades_client_juridic = dades_client_juridic.replace("#codis_centre", "")

                    if placeholders_dict["#País_Client"] == "ESP":
                        dades_client_juridic = dades_client_juridic.replace("#address", address_spain_client)
                        dades_client_juridic = dades_client_juridic.replace("#addcentro", address_spain_centro)
                    else:
                        dades_client_juridic = dades_client_juridic.replace("#address", address_overseas_client)
                        dades_client_juridic = dades_client_juridic.replace("#addcentro", address_overseas_centro)
                    for sub_placeholder, sub_valor in placeholders_dict.items():
                        dades_client_juridic = dades_client_juridic.replace(sub_placeholder, sub_valor)
                    contenido = contenido.replace(placeholder, dades_client_juridic)
                else:
                    if placeholders_dict["#País_Client"] == "ESP":
                        dades_client = dades_client.replace("#address", address_spain_client)
                    else:
                        dades_client = dades_client.replace("#address", address_overseas_client)
                    for sub_placeholder, sub_valor in placeholders_dict.items():
                        dades_client = dades_client.replace(sub_placeholder, sub_valor)
                    contenido = contenido.replace(placeholder, dades_client)
            elif placeholder == "#impostos_totals":
                texto_final = "<TaxesOutputs>\n"
                if len(resultado) == 0:
                    texto_final += '''                <Tax>
                            <TaxTypeCode>01</TaxTypeCode>
                            <TaxRate>0.0</TaxRate>
                            <TaxableBase>
                                <TotalAmount>0.0</TotalAmount>
                            </TaxableBase>
                            <TaxAmount>
                                <TotalAmount>0.0</TotalAmount>
                            </TaxAmount>
                        </Tax>\n'''
                else:
                    for impost in resultado:
                        bloc = dades_impost
                        for k, v in impost.items():
                            bloc = bloc.replace(k, str(v))
                        texto_final += bloc
                texto_final += "            </TaxesOutputs>"
                contenido = contenido.replace(placeholder, texto_final)
                #print(f"{placeholder} => [bloques de impostos insertados]")
            elif placeholder == "#dades_linies": 
                texto_final = "<Items>\n"
                for idx, linia in enumerate(valors_linia_factura):
                    preu_descomptes = 0
                    bloc = dades_linies
                    for i, valor in enumerate(linia):
                        if i == 4:
                            valor = codi_unitat(valor)
                        bloc = bloc.replace(placeholders_linia_factura[i], str(valor))
                    # Calcular #Preu_linia
                    try:
                        quantitat = float(linia[0])
                        preu_unitari = float(linia[3])
                        preu_total = round(quantitat * preu_unitari, 2)
                        preu_descomptes = preu_total
                    except ValueError:
                        preu_total = "ERROR"
                    bloc = bloc.replace("#Preu_linia", str(preu_total))
                    # Descomptes per aquesta línia
                    descomptes = valors_descomptes[idx] if idx < len(valors_descomptes) else []
                    if descomptes:
                        texto_final_desc = "<DiscountsAndRebates>\n"
                        for descompte in descomptes:
                            descripcio = descompte[0] if descompte[0] else "Descompte"
                            try:
                                base = float(descompte[1])
                            except ValueError:
                                base = 0.0
                            try:
                                percentatge = float(descompte[2]) if descompte[2] else None
                            except ValueError:
                                percentatge = None
                            texto_final_desc += "                        <Discount>\n"
                            texto_final_desc += f"                            <DiscountReason>{descripcio}</DiscountReason>\n"
                            if percentatge is not None:
                                texto_final_desc += f"                            <DiscountRate>{percentatge}</DiscountRate>\n"
                            texto_final_desc += f"                            <DiscountAmount>{float(descompte[3])}</DiscountAmount>\n"
                            texto_final_desc += "                        </Discount>\n"
                            preu_descomptes -= float(descompte[3])
                        texto_final_desc += "                    </DiscountsAndRebates>"
                        bloc = bloc.replace("#descomptes_linia", texto_final_desc)
                    else:
                        bloc = "\n".join([line for line in bloc.splitlines() if "#descomptes_linia" not in line])     
                    bloc = bloc.replace("#preu_descomptes", str(preu_descomptes))
                    texto_final += bloc
                    # Impostos per aquesta línia
                    imposts = valors_impostos[idx] if idx < len(valors_impostos) else []
                    #print(f"imposts: {imposts}")
                    impostos_agregats_linia = defaultdict(lambda: {
                        '#Base_imposable_Impost_Linia': 0,
                        '#Total_Impost_Linia': 0
                    })
                    for entrada in imposts:
                        if len(entrada) < 2:
                            continue  # Salta si no hay al menos nombre y base
                        nom = entrada[0]
                        codi = codi_tipus_impost(nom)
                        base_str = entrada[1]
                        tipus = entrada[2] if len(entrada) > 2 and entrada[2] not in (None, '', 'null') else "100"
                        total_str = entrada[3] if len(entrada) > 3 and entrada[3] not in (None, '', 'null') else base_str
                        try:
                            base = float(base_str)
                            total = float(total_str)
                        except ValueError:
                            continue  # Salta si base o total no son números
                        key = (codi, tipus)
                        impostos_agregats_linia[key]['#impost_Impost_Linia'] = codi
                        impostos_agregats_linia[key]['#Tipus_impositiu_Impost_Linia'] = tipus
                        impostos_agregats_linia[key]['#Base_imposable_Impost_Linia'] += base
                        impostos_agregats_linia[key]['#Total_Impost_Linia'] += total
                    # Convertimos a lista de diccionarios
                    resultado_linia = list(impostos_agregats_linia.values())
                    #print(f"resultado_linia: {resultado_linia}")
                    texto_final_imp = "<TaxesOutputs>\n"
                    if len(resultado_linia) == 0:
                        texto_final_imp += '''                        <Tax>
                                    <TaxTypeCode>01</TaxTypeCode>
                                    <TaxRate>0.0</TaxRate>
                                    <TaxableBase>
                                        <TotalAmount>0.0</TotalAmount>
                                    </TaxableBase>
                                    <TaxAmount>
                                        <TotalAmount>0.0</TotalAmount>
                                    </TaxAmount>
                                </Tax>\n'''
                    else:
                        for impost in resultado_linia:
                            bloc_imp = dades_impost_linia
                            for k, v in impost.items():
                                bloc_imp = bloc_imp.replace(k, str(v))
                            texto_final_imp += bloc_imp
                    texto_final_imp += "                    </TaxesOutputs>"
                    #print(f"texto_final_imp: {texto_final_imp}")
                    texto_final = texto_final.replace("#impostos_linia", texto_final_imp)
                texto_final += "\n            </Items>"
                contenido = contenido.replace(placeholder, texto_final)
            elif placeholder == "#pagaments_anticipats":
                contenido = contenido.replace(placeholder, text_final_anticipats)
            elif placeholder == "#total_anticipats":
                text_total_pagaments_anticipats = '''<TotalPaymentsOnAccount>''' + str(sum_pagaments_anticipats) + '''</TotalPaymentsOnAccount>'''
                contenido = contenido.replace(placeholder, text_total_pagaments_anticipats)
            elif placeholder == "#dades_literals":
                texto_final_literals = ""
                if len(dades_circumstancia) > 0:
                    texto_final_literals = '''<LegalLiterals>
'''
                    for circ in dades_circumstancia: 
                        texto_final_literals += '''                <LegalReference>''' + circ[0] + '''</LegalReference>
'''
                    texto_final_literals += '''            </LegalLiterals>'''
                contenido = contenido.replace(placeholder, texto_final_literals)


        with open(os.path.join(dest_path, serie + "-" + numero_factura + ".xml"), "w", encoding="utf-8") as f:
            f.write(contenido)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()