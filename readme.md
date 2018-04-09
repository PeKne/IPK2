# IPK2: DNS lookup tool

Jednoduchá aplikace která zasílá dotazy DNS serveru a interpretuje odpovědi.

## Sestavení
Pro překlad, v pracovním adresáři spustě Makefile pomocí příkazu 'make'

```
user@machine:~$ make
    gcc  ipk-lookup.c -o ipk-lookup
```
## Spuštění

aplikace má dva povinné parametry:
*  -s [nazev DNS serveru] (dotazovaný DNS server)
*  [name] (překládané doménové jméno)

a čtyři volitelné parametry:

*  -h (je vytištěna nápověda a program končí)
*  -t [type] (typ hledaného záznamu)
*  -T [timeout] (timeout pro dotaz)
*  -i (ierativní lookup)

```
./ipk-lookup -s 8.8.8.8 -t A www.fit.vutbr.cz
```
## Autor

* **Petr Knetl** (xknetl00)
