import tkinter as tk

#####################################

def ROT13toBit(texto_de_entrada):
    rot13_texto = ''
    for char in texto_de_entrada:
        if 'A' <= char <= 'Z':
            rot13_texto += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        elif 'a' <= char <= 'z':
            rot13_texto += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        else:
            rot13_texto += char
    bit_de_salida = ' '.join(format(ord(c), '08b') for c in rot13_texto)
    return bit_de_salida

def BitToROT13(bit_de_entrada):
    chars = bit_de_entrada.split()
    text = ''.join(chr(int(b, 2)) for b in chars)
    texto_original = ''
    for char in text:
        if 'A' <= char <= 'Z':
            texto_original += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        elif 'a' <= char <= 'z':
            texto_original += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        else:
            texto_original += char
    return texto_original

#Entrada desde terminal
mensaje = input("Escribe el mensaje que quieres cifrar y luego recuperar: ")

#Cifrado ROT13 a binario
cifrado = ROT13toBit(mensaje)
print("El mensaje cifrado en bits es:", cifrado)

#Desencriptado desde bits a texto original
descifrado = BitToROT13(cifrado)
print("EL mensaje original recuperado es:", descifrado)

#####################

def StringToROT13(texto):
    resultado = ""
    for c in texto:
        if 'a' <= c <= 'z':
            resultado += chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            resultado += chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
        else:
            resultado += c
    return resultado
def ROT13ToString(texto):
    return StringToROT13(texto)

def mostrarBits(cadenaBits, contenedor, fila, columna):
    anchoCuadro = 30
    altoCuadro = 30
    anchoTotal = len(cadenaBits) * anchoCuadro

    canva = tk.Canvas(contenedor, width=anchoTotal, height=altoCuadro)
    canva.grid(row=fila, column=columna, columnspan=2, pady=10, padx=10)

    for i, bit in enumerate(cadenaBits):
        coordenadaInicial = i * anchoCuadro
        coordenadaFinal = coordenadaInicial + anchoCuadro
        color = "black" if bit == "0" else "white"
        canva.create_rectangle(coordenadaFinal, 0, coordenadaFinal, altoCuadro, fill=color, outline="gray")
    #esto crea un rectangulo con "i" cantidad de cuadros, donde cada cuadro esta formado por las puntos (coordenadaFinal, 0) y (coordeanadaFinal, altoCuadro)
# -*- coding: utf-8 -*-
def xor_list(bit_list):
    """
    XOR acumulativo de una lista/iterable de bits (0/1).
    Devuelve 0 o 1.
    """
    resultado = 0
    for bit in bit_list:
        resultado ^= int(bit)
    return resultado


def decodificar_y_corregir_hamming_full(palabra_recibida: str):
    """
    Verifica una palabra de código de 12 bits (Hamming 12,8),
    corrige un error de un solo bit (si la posición está en 1..12),
    extrae los 8 bits de datos originales y devuelve:
      (datos_corregidos_str, palabra_corregida_12bits_str, posicion_error)
    Si el síndrome indica una posición fuera de 1..12, no corrige y avisa.
    """
    if len(palabra_recibida) != 12:
        raise ValueError("Se requieren 12 bits de palabra de código.")

    # Convertir a lista de enteros e añadir elemento 0 al inicio para usar índices 1..12
    palabra = [0] + [int(b) for b in palabra_recibida]

    # Calcular bits de chequeo (síndrome) usando XOR sobre las posiciones indicadas
    c1 = xor_list([palabra[i] for i in [1, 3, 5, 7, 9, 11]])
    c2 = xor_list([palabra[i] for i in [2, 3, 6, 7, 10, 11]])
    c4 = xor_list([palabra[i] for i in [4, 5, 6, 7, 12]])
    c8 = xor_list([palabra[i] for i in [8, 9, 10, 11, 12]])

    # Síndrome en orden MSB->LSB: c8 c4 c2 c1
    sindrome_binario = f"{c8}{c4}{c2}{c1}"
    posicion_error = int(sindrome_binario, 2)

    # Manejo del síndrome
    if posicion_error == 0:
        print("  [ESTADO]: No se detectaron errores de un solo bit.")
    elif 1 <= posicion_error <= 12:
        print(f"  [ERROR DETECTADO]: Síndrome {sindrome_binario} -> posición {posicion_error}.")
        # invertir el bit erróneo
        palabra[posicion_error] = 1 - palabra[posicion_error]
        print(f"  [CORRECCIÓN]: Bit en posición {posicion_error} invertido.")
    else:
        # posición fuera del rango 1..12 => posible doble error o palabra inválida
        print(f"  [AVISO]: Síndrome {sindrome_binario} indica posición {posicion_error} fuera de 1..12.")
        print("  Esto puede indicar un error de más de 1 bit o una palabra corrupta; no se corrige.")

    # Extraer los bits de datos en el orden D1..D8 (posiciones 3,5,6,7,9,10,11,12)
    posiciones_datos = [3, 5, 6, 7, 9, 10, 11, 12]
    datos_corregidos = "".join(str(palabra[i]) for i in posiciones_datos)

    # Reconstruir la palabra corregida completa (índices 1..12)
    palabra_corregida = "".join(str(palabra[i]) for i in range(1, 13))

    return datos_corregidos, palabra_corregida, posicion_error


def comparar_palabras(original: str, corregida: str):
    """
    Compara dos palabras de 12 bits (original vs corregida) y devuelve una lista con
    las diferencias encontradas. Cada elemento es un dict:
      {
        'pos_global': int,        # 1..12
        'bit_original': '0'/'1',
        'bit_corregido': '0'/'1',
        'tipo': 'paridad'|'dato',
        'dato_indice': None|1..8
      }
    """
    # Ajustar longitud si es necesario (padding con '0' por seguridad)
    maxlen = max(len(original), len(corregida))
    orig = original.ljust(maxlen, '0')
    corr = corregida.ljust(maxlen, '0')

    posiciones_paridad = {1, 2, 4, 8}
    posiciones_datos = [3, 5, 6, 7, 9, 10, 11, 12]  # mapeo a D1..D8

    diffs = []
    for i in range(maxlen):
        bo = orig[i]
        bc = corr[i]
        if bo != bc:
            pos = i + 1
            if pos in posiciones_paridad:
                tipo = 'paridad'
                dato_idx = None
            else:
                tipo = 'dato'
                try:
                    dato_idx = posiciones_datos.index(pos) + 1
                except ValueError:
                    dato_idx = None
            diffs.append({
                'pos_global': pos,
                'bit_original': bo,
                'bit_corregido': bc,
                'tipo': tipo,
                'dato_indice': dato_idx
            })
    return diffs



def crearVentanaVisualizacion():
    segundaVentana = tk.Toplevel(menu)
    segundaVentana.title("Proceso de encriptación paso a paso")
    
    botonContinuar = tk.Button(segundaVentana, text="Ver mensaje resultante", command=lambda:[segundaVentana.destroy(), crearVentanaResultado("pepe")])
    botonContinuar.grid(row=1, columnspan=2, pady=10, padx=10)

def crearVentanaResultado(mensajeDesencriptado):
    terceraVentana = tk.Toplevel(menu)
    terceraVentana.title("Mensaje Desencriptado")

    tk.Label(terceraVentana, text="El texto que encriptaste y que ha sido desencriptado es el siguiente: ").grid(row=0,column=0, pady=10, padx=10)
    tk.Label(terceraVentana, text=mensajeDesencriptado).grid(row=0,column=1, padx=10, pady=10)

    botonCerrar = tk.Button(terceraVentana, text="Cerrar/Volver al menú principal", command=terceraVentana.destroy)
    botonCerrar.grid(row=1, columnspan=2, pady=10, padx=10)
    

menu = tk.Tk()
menu.title("Sistema de encriptación - IPC G#3")
menu.grid_rowconfigure(0, weight=1)
menu.grid_columnconfigure(0, weight=1)

tk.Label(menu, text="Sistema de encriptacion avanzado yeah").grid(row=0,columnspan=2, pady=10)
inputMensaje = tk.Entry(menu)
tk.Label(menu, text="Ingresa el mensaje que deseas encriptar y mandar: ").grid(row=1,column=0, padx=10)
inputMensaje.grid(row=1,column=1, padx=10)
boton = tk.Button(menu, text="Encriptar mensaje",command=crearVentanaVisualizacion)
boton.grid(row=2, pady=10, columnspan=2)


menu.mainloop() 



