# Como compilar

## Para compilar no Windows, use o passo abaixo:
```bash
# Baixe o sdk do npcap do Windows:
# Descompacte todo o arquivo:
# Copie e cole os dados no caminho:
C:\Program Files\Npcap/
# Porem, deve ter o Npcap instalado:

# Apos isso, compilar com:
gcc -o arp_capture mainWindows.c -I"C:\\Program Files\\Npcap\\Include" -L"C:\\Program Files\\Npcap\\Lib" -lwpcap -lws2_32 --static

```

## Para executar:
Exemplo de Execucao
Se o programa list_devices.exe retornar algo como:

```bash
\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} - Ethernet
\Device\NPF_{YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYYY} - Wi-Fi
```
Entao, voce deve executar seu programa arp_capture.exe da seguinte forma:

```bash
arp_capture.exe \Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
```
Exemplo Atualizado do Comando de Execucao
```bash
arp_capture.exe \Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
```
Substitua \Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} pelo nome da interface correta obtida. Isso deve resolver o problema de abertura do dispositivo.
