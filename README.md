# Generování NetFlow dat ze zachycené síťové komunikace

**Jméno a přijmení:** Václav Korvas

**Login:** xkorva03
        
Projekt do předmětu ISA VUT FIT 2022. Generování NetFlow dat ze zadaného vstupního *pcap* souboru nebo z STDIN. Pomocí argumentů příkazové řádky je pak možné specifikovat na jaký kolektor se mají vygenerované NetFlow záznamy posílat. Jde také specifikovat velikost flow-cache, doby za jakou se mají exportovat aktivní a neaktivní záznamy. Zajímají nás pouze pakety *UDP, *TCP* a *ICMP*. Ostatní pakety jsou vyfiltrovány.

## Vytvoření

Pro vytvoření spustitélného programu stačí použít příkaz `make` popřípadě příkaz `make all`. Tímto příkazem se vytvoří spustitelný soubor v kořenovém adresáři. Pro odstranění spustitelného souboru a všech binárních souborů slouží příkaz `make clean`. Pro úspěšné sestavení programu je potřeba mít nainstalované následující programy: `make, g++` a `knihovnu pcap`.  

## Použití 

```
./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
Options:
    -f <file>                       Soubor .pcap se zachycenou komunikací. Pokud není zadán, čte se ze STDIN. 
    -c <netflow_collector>:<port>   IP adresa, nebo hostname NetFlow kolektoru. volitelně i UDP port (127.0.0.1:2055, pokud není specifikováno),  
    -a <active_timer>               interval v sekundách, po kterém se exportují aktivní záznamy na kolektor (60, pokud není specifikováno)
    -i <inactive_timer>             interval v sekundách, po jehož vypršení se exportují neaktivní záznamy na kolektor (10, pokud není specifikováno),
    -m <count>                      velikost flow-cache. Při dosažení max. velikosti dojde k exportu nejstaršího záznamu v cachi na kolektor (1024, pokud není specifikováno).
    
```

Všechny argumenty jsou volitelné a lze je zadávat v libovolném pořadí. Kolektor je možné zadat i IPv6 adresou. Pokud je ovšem zadán i port je nutné jej zadat následovně: `[IPv6]:port`.

## Implementační detaily

Pokud během programu nastala jakákoliv chyba je program ukončen s `návratovým kódem 1` a korespondující chybová hláška je vypsána na `stderr`. IP adresu je možné zadat jako IPv4 nebo IPv6 adresu, ovšem pokdu je zadána IPv6 adresa i s portem je zadána nasledujícím způsobem: `[IPv6_adresa]:port` u IPv4 ani u doménového jména žádné takové omezení není. Doménové jméno se zadává ve stylu `www.domain.cz:port`.

Pokud je nutné exportovat najednou více flow záznamů. Tak se exportují najednou. Maximální počet takto vyexportovaných flow najednou je 30 podle specifikace. Pro naše účely jsou všechny protokoly kromě `ICMP, UDP a TCP` odfiltrovány. Posledním omezením je, že je možné číst pouze z pcap souborů pakety, které byly zachyceny na ethernetovém rozhraní a jsou zabaleny do ethernet framu. 

## Omezení
Jsou zpracovávány pouze pakety, které obsahují na linkové vrstvě ethernetové hlavičky s hodnotou 
`LINKTYPE_ETHERNET`.

## Příklady spuštění

```
$./flow < icmp.pcap
$./flow -f icmp.pcap -a 60 -i 10 -m 5
$./flow -f icmp.pcap -c localhost:2055
$./flow -f icmp.pcap -c [::1]:2055
$./flow -f tcp.pcap -a 30
```


## Odevzdané soubory

* Makefile
* flow.cpp
* manual.pdf
* README.md
