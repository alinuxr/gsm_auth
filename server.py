import socket
import random
import comp128
import a5
# База данных ключей клиентов
#Тип данных-словарь.Храним ключ:значение
# IMSI:key (K_i)/(ключ аутентификации)
# (128 bit)
data_base = {
    'TestIMSI1': 0x8227bef049c9a51e728d77bd808f877e,
    'TestIMSI2': 0x8227bef049c9a51e728d77bd808f877f
}
def main():
    print('Server ready for mobile stantions\n')
    # Используем библиотеку soket
    # Инициализация сокета.Прослушиваем порт 8888
    #Методом listen запускаем прослушивание.Аргумент-макс.количество подключений в очереди
    sock = socket.socket()
    sock.bind(('', 8888))
    sock.listen(1)
    # Бесконечный цикл прослушивания мобильных станций
    while (1):
        try:
            #метод accept-принимает подключение,возвращает кортеж с двумя элементами: новый сокет и адрес клиента
            conn, addr = sock.accept()
            #выводим на экран адрес подключившего клиента
            print('[!] Connected address: ', addr)
            # Получен IMSI от мобильной станции
            #Получаем порциями по 1024байт
            IMSI = conn.recv(1024).decode()

           #Если он есть в нашей базе данных,то берем соответствующий K_i.Иначе печать об ошибке и закрытие подключения
            if IMSI in data_base:
                secret_key = data_base[IMSI]
            else:
                print('[-] Error IMSI')
                conn.close()
                continue
            # Генерация произвольного значения RAND размером 128 бит
            rand = random.getrandbits(128)
            # Отправка сгенерированного 128-битное случайного числа на Мобильную Станцию (МС)
            conn.send(str(rand).encode())

            # Используем COMP128, чтобы получить XRES и К_с (key_с)/(секретный сессионный ключ для A5)
            # используя секретный ключ МС IMSI_key и алгоритм аутентификации A3/A8.
            h = comp128.run(rand, secret_key)
            h = comp128.to_int(h)

            # 32 старших бита- XRES (expected response)
            xres = (h >> 64) & 0xffff
            # Получить SRES (signed response) от МС
            sres = int(conn.recv(1024).decode())
            # Сравнение SRES и XRES. Если оба значения равны, МС считается аутентифицированной.Иначе вывод об ошибке и закрытие подключения
            if xres == sres:
                print('[+] Authentication passed')
            else:
                print('[-] Error authentication')
                conn.close()
                # return
                continue
            # Младшие 64 бита- К_с
            key_с = h & 0xffffffff
            # Зашифровать сообщение с помощью A5
            data = a5.encrypt('Congratulations! Authentication passed!'.encode(), key_с, 0)
            # Отправить зашифрованное сообщение
            conn.send(data)
            # Получить сообщение
            data = conn.recv(1024)
            # Расшифровать сообщение с помощью A5
            data = a5.encrypt(data, key_с, 1)
            # Напечатать полученное сообщение
            print('Client msg: ', data.decode())

            conn.close()
        except:
            sock.close()
            break
if __name__ == '__main__':
    main()
