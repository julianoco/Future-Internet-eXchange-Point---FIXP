from time import strftime, localtime
import time
#import keyboard
from datetime import datetime, timedelta   #timezone, 
import os

#from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
#from scapy.all import Packet, IPOption
#from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
#from scapy.all import Ether, IP, TCP, UDP, Raw
#from scapy.layers.inet import _IPOption_HDR

#from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
#from scapy.all import Packet, IPOption
#from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
#from scapy.all import Ether, IP, TCP, UDP, Raw
#from scapy.layers.inet import _IPOption_HDR

SWITCH_ATUAL = 's04'

'''
free --kibi | awk '{print $3}'
105744 <- memoria ram utilizada
0      <- processamento utilizado

top -bn 1 | grep 'Cpu(s)' | awk '{print $1, $2, $3, $6, $7}'
$Cpu(s) 0.1 us, 0.0 ni

us. tempo que a cpu gasta em processos do usuario (nao kernel)
ni. tempo gasto em processos de usuasrio ocm prioridade ajustada (valores agradaveis)

'''

linhaArquivo = 1

ARQUITETURA_IPV4   = 0x0800
ARQUITETURA_ETARCH = 0x0880
PRO_TRA            = 0x11 #protocolo de transporte 17 -> UDP
IP_DST             =  '192.168.171.104' #IP DO HOST 01
IP_SRC             =  '192.168.184.102' #IP DO HOST 02
MAC_DST            = '08:00:27:a2:64:af'  #MAC DO HOST 01
MAC_SRC            = '08:00:27:47:2b:1d'  #MAC DO HOST 02 			

I_FACE_ESCUTA = 'eth0'


def preparaListaParaRegistro(linhaArquivoP, listaP, dataComando01P, dataComando02P) :

  listaPreparada = list()

  '''
  i = 0
  for lista in listaP :
    j = 0    
    for elementoLista in lista :
      print("Elemento: ", elementoLista)
      if(not(i == len(listaP) - 1 and j == len(lista) - 1)) :    
        listaP[i][j] = elementoLista + ";"
      j += 1
    i += 1
  '''

  listaPreparada.append([
       str(linhaArquivoP) + ";",  #linha do arquivo
       #str(time.strftime('%Y-%m-%d %H:%M:%S', localtime(dataComando01P)))+";", #datetime da execucao do comando 1       
       str(dataComando01P)+";", #datetime da execucao do comando 1
       str(datetime.timestamp(dataComando01P))+";", #timestamp de execuao do comando 1 
       #str(dataComando01P)+";", #timestamp de execuao do comando 1
       listaP[0][1] + ";", #tempo que a cpu gasta em processos do usuario (nao kernel)
       listaP[0][3] + ";", #tempo gasto em processos de usuasrio ocm prioridade ajustada (valores agradaveis)           
       #str(time.strftime('%Y-%m-%d %H:%M:%S', localtime(dataComando02P)))+";", #datetime da execucao do comando 1       
       #str(dataComando02P)+";", #timestamp de execuao do comando 1
       str(dataComando02P)+";", #datetime da execucao do comando 1
       str(datetime.timestamp(dataComando02P))+";", #timestamp de execuao do comando 1
       listaP[1][1] + ";", #utilizacao de memoria ram da maquina virtual
       listaP[1][2],  #utilizacao de swap da maquina virtual  
       "\n"
  ])
  
  #print("lista: ", listaPreparada)
  #exit(1)
  return listaPreparada
  
def analisaResultadoPS(resultadoPSP, stringP) :
  retornoValor = -1;
  listaBashPID = list()
  listaBashPID = resultadoPSP.split()
  #print("Lista: ", listaBashPID)
  if stringP in listaBashPID :
    retornoValor = listaBashPID[listaBashPID.index(stringP)-3]      
  return retornoValor


def coletaBashPID() :
  #print("Pegando PID do bash corrente .. Inicializando")  
  resultPS = os.popen('ps', 'r', 256).read()
  #print("Resultado do PS : " + resultPS)
  #PID esta tres posicoes anteriores a palavra procurada
  bashPID = analisaResultadoPS(resultPS, "bash")
  #print("bashPID = ", bashPID)  
  #print("Pegando PID do bash corrente .. Concluido")    
  return bashPID
      

def main():

  global linhaArquivo
  global OFFSET
  listaColetaParaArquivo = list()
  listaProcessamentoCPUMemoria = list()

  print("****** INICILIALIZANDO SCRIPT PARA ANALISE DE OVERHEAD NO SWITCH " + SWITCH_ATUAL)  

  print("  Coletando utilizacao de memoria e processamento ...")  

  bashPID = coletaBashPID()
  file = open("/home/student/labs/fixp/overhead_" + SWITCH_ATUAL + "_" + bashPID + ".csv","w")
  file.writelines(["contador; dataExecucaoComando01; timeStampExecucaoComando01; consumoCPU01; consumoCPU02; dataExecucaoComando02; timeStampExecucaoComando02; consumoMemoriaRAM; consumoSWAP\n"])      

  while True :
    #time.sleep(0.001)
    #if keyboard.is_pressed('w') :
    #  print("\n Tecla q ou Q foi pressionada!")
    #  break
    #else :

    #dataAtualComando01 = datetime.now()
    #modificacao inicio
    dataAtualComando01 = datetime.now() - timedelta(seconds=OFFSET)
    #dataAtualComando01 = time.time() - OFFSET
    #print("norario: " + str(time.time()))
    #modificacao fim

    resultComando01 = os.popen("top -bn 1 | grep 'Cpu(s)' | awk '{print teste $1, $2, $3, $6, $7}'", 'r', 256).read()        
    listaProcessamentoCPUMemoria.append(resultComando01.split())
    #print("Lista1:", listaProcessamentoCPUMemoria)
        
    #dataAtualComando02 = datetime.now()
    #modificacao inicio
    dataAtualComando02 = datetime.now() - timedelta(seconds=OFFSET)
    #dataAtualComando02 = time.time() - OFFSET
    #modificacao fim

    resultComando02 = os.popen("free --k | awk '{print $3}'", 'r', 256).read()        
    listaProcessamentoCPUMemoria.append(resultComando02.split())
    #print("Lista2:", listaProcessamentoCPUMemoria)
	
    listaColetaParaArquivo = preparaListaParaRegistro(linhaArquivo, listaProcessamentoCPUMemoria, dataAtualComando01, dataAtualComando02)

    #print("Lista final: ", listaColetaParaArquivo)
    #print("Lista final: ", listaProcessamentoCPUMemoria)      
    #print("Lista final: ", listaColetaParaArquivo)
    #print("Lista final: ", listaProcessamentoCPUMemoria)      

    file.writelines(listaColetaParaArquivo[0])      
    file.flush()

    print(".", flush=True, end=" ")
      
    listaProcessamentoCPUMemoria.clear()
    listaColetaParaArquivo.clear()
    #if linhaArquivo == 50 :
    #  exit(1)
    linhaArquivo += 1     	

  file.close()

  print("\n*** Fim de Programa!")

#inicio modificacao
def analisaResultadoPS(resultadoPSP, stringP) :

  retornoValor = -1;
  listaBashPID = list()
  listaBashPID = resultadoPSP.split()
  #print("Lista: ", listaBashPID)
  if stringP in listaBashPID :
    retornoValor = listaBashPID[listaBashPID.index(stringP)-3]      
  return retornoValor
#fim modificacao


if __name__ == '__main__':

  global OFFSET
  OFFSET = -1

  #inicio modificacao
  resultPS = os.popen('ps', 'r', 256).read()
  bashPID = analisaResultadoPS(resultPS, "bash")

  arquivo  = open('/home/student/labs/fixp/NTPClient/offsetNTPDate'+str(bashPID)+'.drift', 'r')
  
  OFFSET   = float(arquivo.readline())
  arquivo.close
  #fim modificacao

  #filtro = '''ether proto ''' + str(ARQUITETURA_IPV4) + ''' and host ''' + IP_SRC + ''' or ''' + IP_DST + ''' and
  #	      ip proto ''' + str(PRO_TRA)
  #print("filtro: ", filtro)
  #print("Escutando interface " + I_FACE_ESCUTA)
  #sniff(iface=I_FACE_ESCUTA, filter = filtro, prn = lambda x: main(x), count = 1)  

  print("Inicializando em 5 segundos .....")
  time.sleep(5)  
  main()
  
  

