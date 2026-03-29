#passa uma string (result) e devolve uma informacao dessa result que esta entre palavraInicial e palavraFinal, pode devolver uma
#lista de informacoes caso tenha varias palavras iniciais e finais dentro dessa result
#se palavra inicial tiver espaco no final tem que colocar

import os
import time

def retornaHandlesList(result, palavraInicial, palavraFinal = ".") :

  retorno = list()

  resultado = result.lower()

  if(resultado.find("erro") != -1 or resultado.find("invalid") != -1) :
    return(["-1"])

  while(resultado.find(palavraInicial) != -1) :

    if(resultado.find(palavraFinal) > resultado.find(palavraInicial)) :

      retorno.append(resultado[(resultado.find(palavraInicial)+len(palavraInicial)):resultado.find(palavraFinal)])

    resultado = resultado[(resultado.find(palavraFinal)+1):len(resultado)]
    
  return retorno

def analisaResultadoPS(resultadoPSP, stringP) :
  retornoValor = -1;
  listaBashPID = list()
  listaBashPID = resultadoPSP.split()
  print("Lista: ", listaBashPID)
  if stringP in listaBashPID :
    retornoValor = listaBashPID[listaBashPID.index(stringP)-3]      
  return retornoValor



def main():

  print("****** INICILIALIZANDO SCRIPT PARA SINCRONIZACAO DA MAQUINA NTP CLIENT ")
  
  
  print("Pegando PID do bash corrente .. Inicializando")  
  resultPS = os.popen('ps', 'r', 256).read()
  print("Resultado do PS : " + resultPS)
  #PID esta tres posicoes anteriores a palavra procurada
  bashPID = analisaResultadoPS(resultPS, "bash")
  print("bashPID = ", bashPID)  
  print("Pegando PID do bash corrente .. Concluido")    
  #exit(1)

  print("Comando para desabilitar servico linux que sincroniza horarios .... Inicializando")  
  os.popen('systemctl disable systemd-timesyncd.service', 'r', 256).read()
  print("Comando para desabilitar servico linux que sincroniza horarios .... Concluido")  
  print("Comando para parar servico linux que sincroniza horarios .... Inicializando")    
  os.popen('systemctl stop systemd-timesyncd.service', 'r', 256).read()
  print("Comando para parar servico linux que sincroniza horarios .... Concluido")  
  print("Comando para configurar o fuso horario do cliente (UTC) .... Inicializando")    
  os.popen('timedatectl set-timezone UTC', 'r', 256).read()
  print("Comando para configurar o fuso horario do cliente (UTC) .... Concluido")    
  print("Comando para sicronizar horarios com NTP server...Inicializando")      
    
  cmdNPTDate = "ntpdate 192.168.1.51"
  retornoComando1 = '10.00'
  contador = 1
  while(int(retornoComando1[0:retornoComando1.find('.')])!=0) :
    if contador != 1 :
      time.sleep(5)
    retornoComando  = os.popen(cmdNPTDate, 'r', 256).read()
    retornoComando1 = retornaHandlesList(retornoComando, "offset ", " sec")[0]
    print(retornoComando1)
    print(int(retornoComando1[0:retornoComando1.find('.')]))
    print(int(retornoComando1[0:retornoComando1.find('.')])!=0)
    print("contador: ", contador)
    contador+=1
    
    #exit(1)
    
  print("pasou aqui!")
  
  print("Comando para sicronizar horarios com NTP server...Concluido")        
  #print("Teste Retorno: ", retornaHandlesList(retornoComando, "offset ", " sec"))  
  print("Registrando offset do NTP Client em relacao ao servidor NTP...Inicializando")      
  print("  retornoComando = ", retornoComando)
  file = open("/root/fixp//NTPClient/offsetNTPDate" + bashPID + ".drift","w")
  file.writelines(retornaHandlesList(retornoComando, "offset ", " sec"))      
  file.close()
  print("Registrando offset do NTP Client em relacao ao servidor NTP...Concluido")         
  
if __name__ == '__main__':
  main()
