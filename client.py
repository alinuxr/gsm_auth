import socket
import comp128
import a5
IMSI = 'TestIMSI1'
# 128 key (K_i)/(ключ аутентификации)
IMSI_key = 0x8227bef049c9a51e728d77bd808f877e
def main():
    # Инициализация сокета.Подключаемся к хосту(вместо IP адреса у нас localhost) с указанием порта.
    sock = socket.socket()
    sock.connect(('localhost', 8888))
    # Отправка IMSI Центру Аутентификации (ЦА)
    sock.send(IMSI.encode())
    try:
        # Получаем 128-битное значение RAND
        rand = int(sock.recv(1024).decode())
        #В случае если "поймали" ошибку, то вывод об ошибке и закрытие соединения
    except Exception as e:
        print('[-] Error connected server')
        sock.close()
        return
    # Используем COMP128, чтобы получить SRES и К_с (key_с)/(секретный сессионный ключ для A5)
    # используя свой секретный ключ IMSI_key и алгоритм аутентификации A3/A8.
    h = comp128.run(rand, IMSI_key)
    h = comp128.to_int(h)

    # 32 старших бита- SRES
    #получаем их побитово сдвигая вправо на 64, поскольку всего у нас 96 бит,то получаем 32 бита
    sres = (h >> 64) & 0xffff
    # Отправить полученный SRES (signed response) обратно на ЦА
    sock.send(str(sres).encode())

    # младшие 64 бита- Kc
    key_с = h & 0xffffffff
    # Получить сообщение
    data = sock.recv(1024)
    try:
        # Расшифровать сообщение с помощью A5
        data = a5.encrypt(data, key_с, 0)
    #В случае если "поймали" ошибку, то вывод об ошибке и закрытие соединения
    except Exception as e:
        print('[-] Error encrypted A5')
        sock.close()
        return
    # Напечатать полученное сообщение
    print('[!] Server msg: ', data.decode())
    # Зашифровать сообщение с помощью A5
    data = a5.encrypt('Hello, server! '.encode(), key_с, 1)
    # Отправить зашифрованное сообщение и закрыть соединение
    sock.send(data)
    sock.close()
if __name__ == '__main__':
    main()
