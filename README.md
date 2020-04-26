# Projekt pre predmet IPK
## Packet sniffer - varianta [ZETA]

__Spustenie projektu:__

V priečinku projektu sa nachádza Makefile, ktorý umožní projekt zostaviť použitím:

_make_

Vyčistenie zkompilovaného programu ipk-sniffer je možné pomocou:

_make clean_

Projekt sa spúšta pomocou:

_./ipk-sniffer -i rozhranie [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]_

Pokiaľ nie je možné projekt spustiť je potrebné mu poskytnúť administrátorské práva:

_sudo ./ipk-sniffer -i rozhranie [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]_

Nápovedu je možné zobraziť pomocou prepínaču __-h__ 

V prípade chybných argumentov alebo bola vyžiadaná nápoveda, program skončí s návratovou hodnotou __1__

V prípade úspechu vráti hodnotu __0__

V prípade zlyhania súčastí knižnice PCAP vráti hodnotu __10__

V prípade zlyhania funkcie callback vráti hodnotu __20__

__Obsah archívu__
v archíve xbobos00.tar sa nachádza program: Makefile, projekt: ipk-sniffer.c, toto README.md a dokumentácia: manual.pdf .