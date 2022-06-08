"""
Vypracoval: Martin Hric
PKS UDP komunikator
2021/2022
"""
import socket
import queue
import math
import threading
import os
import libscrc

initial_fragment = (1).to_bytes(1, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2,"big")
CORR = True
FAILED_COUNT = 1 #kolko ma byt corruptnutych bytov

#funkcia na zistenie ip adresy, vzhladom k tomu ze je to po ethernete tak na druhom pocitaci mi nefungovalo socket.gethostbyname(socket.gethostname()), vypisovalo mi IP v loopbacku a to ja nechcem
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

#IP check
def check_ip(IP):
    try:
        socket.inet_aton(IP)
    except:
        return False
    return True

#funkcia na vytvorenie fragmentov a vlozenie fragmentov do queue
def make_fragments(message, fragment_size):

    fragment_queue = queue.Queue()
    start = 0
    index = 0

    if fragment_size == 0:              #nastavim automaticky velkost
        if len(message) >= 1463:
            fragment_size = 1463
        else:
            fragment_size = len(message)

    n_of_fragments = int(math.ceil(float(len(message)) / float(fragment_size)))

    if fragment_size > len(message):
        fragment_size = len(message)

    end = fragment_size

    print(f"velkost fragmentu nastavena na: {fragment_size}")


    while True:

        if start + fragment_size >= len(message):
            end = len(message)
            fragment = message[start:end]
            fragment = (2).to_bytes(1, "big") + fragment_size.to_bytes(2, "big") + n_of_fragments.to_bytes(2, "big") + index.to_bytes(2, "big") + fragment
            fragment += libscrc.ibm(fragment[7:]).to_bytes(2, "big")
            fragment_queue.put(fragment)
            break
        else:
            fragment = message[start:end]
            fragment = (2).to_bytes(1, "big") + fragment_size.to_bytes(2, "big") + n_of_fragments.to_bytes(2, "big") + index.to_bytes(2, "big") + fragment
            fragment += libscrc.ibm(fragment[7:]).to_bytes(2, "big")
            index += 1
            start += fragment_size
            end += fragment_size
            fragment_queue.put(fragment)

    return fragment_queue

#keep_alive kazdych 25 sekund posielana
def keep_alive(event, sock, ip, port):
    while not event.isSet():
        is_set = event.wait(25)
        if not is_set:
            keep_alive_fragment = (4).to_bytes(1, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2,"big")
            sock.sendto(keep_alive_fragment, (ip, port))

#hlavna funckia pre klienta ktora posiela fragementy a po 10 odoslanych alebo posledneho fragmentu caka na kontrolu spravnosti
def send(ip, port, fragment, message, path ,socked=0):

    if socked == 0:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(initial_fragment, (ip, port))
        try:
            data, address = sock.recvfrom(2048)
            if int.from_bytes(data[0:1], "big") == 1:
                print("Spojenie bolo vytvorene")
        except:
            print("Nenastalo spojenie...")
            main()
    else:
        sock = socked                 #ak uz je socket vytvoreny, pouzivam ten z predoslej komunikacie

    fragmenty = make_fragments(message,fragment)

    print(f"{fragmenty.qsize()} fragmentov bude poslanych")

    if path == 0:      #ak path je 0, to znamena ze sprava bude posielana
        fragment = (2).to_bytes(1, "big") + (0).to_bytes(2, "big") + (fragmenty.qsize()).to_bytes(2, "big") + (0).to_bytes(2,"big")
    else:
        filename = os.path.basename(path)
        fragment = (2).to_bytes(1, "big") + (len(filename)).to_bytes(2, "big") + (fragmenty.qsize()).to_bytes(2, "big") + (0).to_bytes(2, "big") + bytes(filename, "ascii")

    #odosle hlavicku serveru obsahujucu kolko fragmentov bude poslanych a nazov suboru pokial je to subor
    sock.sendto(fragment, (ip, port))
    all_fragments = list(fragmenty.queue)

    global CORR
    failed_count = 0
    ten_count = 0
    ack_count = 0
    nack_count = 0

    while not fragmenty.empty():
        count = 0
        while count != 10 and not fragmenty.empty():
            fragment = fragmenty.get()

            if CORR:
                fragment = bytearray(fragment)
                failed_count += 1
                try:
                    fragment[7] = fragment[7]+1
                except ValueError:
                    fragment[7] = fragment[7]-1
                fragment = bytes(fragment)
                if failed_count == FAILED_COUNT:
                    CORR = False


            sock.sendto(fragment, (ip, port))     #odosiela vsetky fragmenz

            count += 1
        while True:

            data, address = sock.recvfrom(1024)             #kontroluje spravu od servera ci boli spravne, ak neboli, tak ich da naspat do queue a vypise presne ktore boli neuspesne
            if int.from_bytes(data[0:1], "big") == 5:
                print(f"Davka c.{ten_count} uspesne dorucena")
                ten_count += 1
                ack_count += 1
                break
            elif int.from_bytes(data[0:1], "big") == 3:
                n_of_failed = int(int.from_bytes(data[3:5], "big"))
                for i in range(n_of_failed):
                    fragmenty.put(all_fragments[int.from_bytes(data[7+i*2:7+i*2+2], "big")])
                print(f"Davka c.{ten_count} neuspesne dorucena")
                failed = ""
                for i in range(n_of_failed):
                    failed += str(int.from_bytes(data[7+i*2:7+i*2+2], "big")) + " "
                print(f"Fragmenty [ {failed}] boli neuspesne...")
                ten_count += 1
                nack_count += 1
                break

    print(f"pocet prijatych ACK: {ack_count}")
    print(f"pocet prijatch NACK: {nack_count}")
    end_menu(ip, port, sock)

#funkcia pre server, ktora parsuje prijate data
def parser(data):
    fragment = {'type': int.from_bytes(data[0:1], "big"), 'data_length': int.from_bytes(data[1:3], "big"),
                'total_n': int.from_bytes(data[3:5], "big"), 'order': int.from_bytes(data[5:7], "big"),
                'data': data[7:]}
    return fragment

#end menu, ako pokracovat, zapina sa thread na keepalive
def end_menu(ip,port,sock):
    event = threading.Event()
    thread = threading.Thread(target=keep_alive, daemon=True, args=(event, sock, ip, port))
    thread.start()

    print("Ako si zelate pokracovat? ZMENIT ROLU(0) , POSLAT DATA na rovnaky server(1) , ZMENIT SERVER(2) , UKONCIT(3):",end='')
    answer = int(input())

    if answer == 0:
        event.set()
        main()
    elif answer == 1:
        print("INPUT FRAGMENT SIZE(1-1463) || 0 for automatic: ", end='')
        FRAGMENT_SIZE = int(input())
        if FRAGMENT_SIZE < 0 or FRAGMENT_SIZE > 1463:
            print("INVALID FRAGMENT SIZE")
            exit()

        print("INPUT TYPE NUMBER -> MESSAGE(0) OR FILE(1): ", end='')
        MESSAGE_TYPE = int(input())
        MESSAGE = '0'
        PATH = 0
        if MESSAGE_TYPE == 0:
            print('TYPE THE MESSAGE ->', end='')
            MESSAGE = bytearray(str(input()), 'ascii')
        elif MESSAGE_TYPE == 1:
            print("INPUT FILE PATH: ", end='')
            try:
                PATH = str(input())
                MESSAGE = open(PATH, 'rb').read()
            except:
                print("CANNOT OPEN FILE")
                exit()
        else:
            print("INVALID TYPE")
            exit()

        print("DO YOU WANT DATA TO BE CORRUPTED? YES(1) OR NO(2): ", end='')
        corr = int(input())
        global CORR
        if corr == 1:
            CORR = True
        elif corr == 2:
            CORR = False
        else:
            print("INVALID INPUT")
            main()

        event.set()
        send(ip, port, FRAGMENT_SIZE, MESSAGE, PATH,sock)

    elif answer == 2:
        event.set()
        start_client()
    elif answer == 3:
        exit()

#hlavna funkcia serveru
def start_server():
    print("PORT(5000-65535): ", end='')
    PORT = int(input())
    if 5000 > PORT < 65535:
        print("INVALID PORT")
        exit(1)

    IP = get_ip_address()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((IP, PORT))

    print(f"[LISTENING]Server bezi na porte {PORT}")

    while True:
        sock.settimeout(None) #moznost nastavit timeout
        while True:
            try:
                data
            except:           #ak este data neexistuju, takze pride len prva iteracia
                data, address = sock.recvfrom(2048)
                p_data = parser(data)
                if p_data['type'] == 1:
                    print("Spojenie inicializovane klientom")
                    sock.sendto(data, address)

                data, address = sock.recvfrom(2048)
            p_data = parser(data)
            total_fragments = p_data['total_n']
            print(f"{total_fragments} fragmentov bude prijatych")

            # ked data_lentgh je 0 to znamena ze sprava bude poslana
            if p_data['data_length'] == 0:
                typ = 1
                break
            else:
                typ = 2
                filename = data[7:].decode("ascii")
                break


        counter = 0
        total_counter = 0
        to_be_reviewed = []
        reviewed = {}
        failed = []
        end_data = bytearray()
        sock.settimeout(1)

        while total_counter != total_fragments:
            try:
                data, address = sock.recvfrom(2048)
            except:  #ak vobec nepride
                print(f"Davka c.{int(total_counter / 2)} neprisla ")

                if total_counter - counter + 10 > total_fragments:
                    for i in range(total_fragments - total_counter + counter):
                        failed.append(total_counter - counter + i)
                else:
                    for i in range(10):
                        failed.append(total_counter - counter + i)

                ack = (3).to_bytes(1, "big") + (len(failed) * 2).to_bytes(2, "big") + (len(failed)).to_bytes(2,"big") + (0).to_bytes(2, "big")

                #posle klientovi ktore fragmenty treba este znova poslat
                for i in failed:
                    ack += i.to_bytes(2, "big")
                sock.sendto(ack, address)
                failed = []
                to_be_reviewed = []
                total_counter -= counter
                counter = 0
                continue

            #ak pride fragment, kontroluje sa pomocou kniznice libscrc.imb [crc 16] , ci je spravny
            counter += 1
            total_counter += 1
            fragment = data[:]
            to_be_reviewed.append(fragment)

            #kontroluju sa po desiatkach alebo ak je to posledny fragment
            if counter % 10 == 0 or total_counter == total_fragments:

                for i in to_be_reviewed: #hlada to crc
                    if int.from_bytes(i[len(i) - 2:], "big") == libscrc.ibm(i[7:len(i) - 2]):
                        reviewed[int.from_bytes(i[5:7], "big")] = i[7:len(i) - 2]
                    else:
                        total_counter -= 1 #ak je nespravny, priradzuje sa do failed listu, odpocitava sa 1 pretoze samozrejme ze musi to zbehnut tolko krat viac
                        failed.append(int.from_bytes(i[5:7], "big"))

                if len(failed) == 0: #odosiela pozitivnu spravu o prijati bezchybne
                    print(f"Davka c.{int(total_counter / 10)} prijata bez chyb")
                    ack = (5).to_bytes(1, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2, "big")
                    sock.sendto(ack, address)
                else:    #inak vypise ze su nespravne a ich indexy
                    print(f"Davka c.{int(total_counter / 10)} bola poskodena")
                    ack = (3).to_bytes(1, "big") + (len(failed) * 2).to_bytes(2, "big") + (len(failed)).to_bytes(2,"big") + (0).to_bytes(2, "big")
                    corrupted = ""
                    for i in failed:
                        ack += i.to_bytes(2, "big")
                        corrupted += str(i) + " "
                    print(f"Fragmenty [{corrupted} ] boli poskodene alebo chybaju")
                    sock.sendto(ack, address)
                failed = []
                to_be_reviewed = []
                counter = 0

        for i in range(len(reviewed)):
            try:
                end_data += reviewed[i]
            except:
                pass

        if typ == 1:
            message = end_data.decode("ascii")
            print(f"Sprava: {message}")
        else:
            file = open(filename, "wb")
            file.write(end_data)
            print(f"Cesta k suboru: {os.path.dirname(os.path.realpath(__file__))}/{filename}")
            file.close()


        sock.settimeout(30)
        try:
            while True:
                data, address = sock.recvfrom(1024)
                if int.from_bytes(data[:1], 'little') == 4:
                    print("Spojenie je udrziavane klientom")
                    sock.settimeout(30)
                elif int.from_bytes(data[:1], 'little') == 2:
                    break

        except:
            print("Cas spojenia vyprsal.")
            print("Ukoncit? ANO(1) NIE(2)")
            answer = int(input())
            if answer == 1:
                exit()
            else:
                sock.close()
                main()

#nastavovania pre klienta
def start_client():
    print("INPUT IP ADDRESS WHERE TO SEND DATA: ", end='')
    IP_SERVER = str(input())
    if not check_ip(IP_SERVER):
        print("INVALID IP ADDRESS")
        main()

    print("INPUT SERVER PORT(5000-65535): ", end='')
    PORT = int(input())
    if PORT < 5000 or PORT > 65535:
        print("INVALID PORT")
        main()

    print("INPUT FRAGMENT SIZE(1-1463) || 0 for automatic: ", end='')
    FRAGMENT_SIZE = int(input())
    if FRAGMENT_SIZE < 0 or FRAGMENT_SIZE > 1463:
        print("INVALID FRAGMENT SIZE")
        main()

    print("INPUT TYPE NUMBER -> MESSAGE(0) OR FILE(1): ", end='')
    MESSAGE_TYPE = int(input())
    MESSAGE = '0'
    PATH = 0
    if MESSAGE_TYPE == 0:
        print('TYPE THE MESSAGE ->', end='')
        MESSAGE = bytearray(str(input()), 'ascii')
    elif MESSAGE_TYPE == 1:
        print("INPUT FILE PATH: ", end='')
        try:
            PATH = str(input())
            MESSAGE = open(PATH, 'rb').read()
        except:
            print("CANNOT OPEN FILE")
            main()
    else:
        print("INVALID TYPE")
        main()

    print("DO YOU WANT DATA TO BE CORRUPTED? YES(1) OR NO(2): ", end='')
    corr = int(input())
    global CORR
    if corr == 1:
        CORR = True
    elif corr == 2:
        CORR = False
    else:
        print("INVALID INPUT")
        main()

    send(IP_SERVER, PORT, FRAGMENT_SIZE, MESSAGE, PATH)

def main():

    print("CLIENT(0) alebo SERVER(1):",end='')
    choice = int(input())
    if choice == 1:
        start_server()
    else:
        start_client()

main()