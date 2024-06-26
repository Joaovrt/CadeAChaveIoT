//Bibliotecas
#include <Servo.h> //Servo motor
#include <ESP8266WiFi.h> //Wifi
#include <WiFiClientSecure.h> //Requisição HTTPS
#include <Arduino.h> //Leitor RFID
#include <SPI.h> //Leitor RFID
#include <MFRC522.h> //Leitor RFID
#include <CryptoAES_CBC.h>
#include <AES.h>
#include <string.h>
#include <PubSubClient.h>

//Definição de variaveis
#define SS_PIN D8 //Leitor RFID
#define RST_PIN D0 //Leitor RFID
#define pinServo D1 //Servo motor
#define ledVerde D2
#define ledVermelho D3
#define ledBranco D4

Servo fechadura; //Servo motor
MFRC522 rfid(SS_PIN, RST_PIN); //Servo motor
byte nuidPICC[4]; //ID do cartão RFID
bool leituraEfetuada = false; //Controle se a leitura já foi feita
String cpfAdmin="51932861866"; //CPF professor, fixo inicialmente, mas será obtido pelo cartão posteriormente
String cpfDocente="";
String nome = "L21"; //Nome da sala
const char* SSID = "Bueiro"; //Nome do Wifi
const char* PASSWORD = "ProjetoUpx"; //Senha do Wifi
String urlBase = "https://cadeachave-1715465469308.azurewebsites.net/api/sala"; //Url base para abrir ou fechar a sala
String urlAuth = "https://cadeachave-1715465469308.azurewebsites.net/api/user/login"; //Url de autenticação
String login = "hardware"; //Login de usuario da porta
String senha = "hardware123"; //Senha de usuario da porta
unsigned long tempoBateuCartao = 0; //Momento em que o cartão é enconstado
const unsigned long tempoReset = 60000; //Tempo para voltar a ler novamente qualquer cartão encostado
const char fingerprint[] PROGMEM = "51 68 54 2C AD 63 02 B3 5C 86 92 257B 8B 6B 34 A3 CB 2D A4"; //Certificado SSL do site
// Chave de 16 bytes (128 bits) para criptografia
byte chave[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
// Armazena o texto descriptografado após a decodificação
byte decryptedtext[16];
// Objeto da classe AES128
AES128 aes128;
MFRC522::MIFARE_Key key;
// MQTT Broker
const char *mqtt_broker = "test.mosquitto.org";  //Host do broket
const char *topic = "CADEACHAVE/SALA/L21";            //Topico a ser subscrito e publicado
const char *mqtt_username = "";         //Usuario
const char *mqtt_password = "";         //Senha
const int mqtt_port = 1883;             //Porta

//Variáveis
bool mqttStatus = 0;
WiFiClient espClient;
PubSubClient client(espClient);
bool acaoMQTT = false;
unsigned long lastReconnectAttempt = 0;

//Definição de funções
int fazerRequisicaoGet(String path, String token); //Requisicao GET
String fazerRequisicaoPost(); //Requisicao POST
void initWiFi(); //Inicia Wifi
void printHex(byte *buffer, byte bufferSize); //Imprime o ID do cartão
void abrir(String cpf=cpfDocente); //Funcao de abertura
void fechar(String cpf=cpfDocente); //Funcao de fechamento
String extrairToken(String resposta); //Funcao para extrair do do body do json de resposta da rota de autenticação
void modo_leitura();
bool connectMQTT();
void callback(char *topic, byte * payload, unsigned int length);
bool reconnect(); // Nova função para reconexão

void setup() {
  pinMode(ledVerde, OUTPUT);
  pinMode(ledVermelho, OUTPUT);
  pinMode(ledBranco, OUTPUT);
  digitalWrite(ledVerde, HIGH);
  digitalWrite(ledVermelho, HIGH);
  digitalWrite(ledBranco, HIGH);
  Serial.begin(9600); //Estabelece frequencia da comunicação serial
  initWiFi(); //Inicia o Wifi
  //Prepara chave - padrao de fabrica = FFFFFFFFFFFFh
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;
  aes128.setKey(chave, 16); // Define a chave para AES
  SPI.begin(); //Inicializa o leitor RFID
  rfid.PCD_Init(); //Inicializa o leitor RFID
  //Fecha a porta
  fechadura.attach(pinServo); //Inicia o servo motor
  fechadura.write(0);
  fechar(cpfAdmin);
  digitalWrite(ledVerde, LOW);
  digitalWrite(ledVermelho, LOW);
  digitalWrite(ledBranco, LOW);
  mqttStatus =  connectMQTT();
}

void loop() {
   if (!client.connected()) {
    unsigned long now = millis();
    if (now - lastReconnectAttempt > 5000) { // Tenta reconectar a cada 5 segundos
      lastReconnectAttempt = now;
      if (reconnect()) {
        lastReconnectAttempt = 0;
      }
    }
  } else {
    client.loop();
  }
  //Caso tenha se passado o tempo de reset, limpa a informação do último cartão lido
  if (millis() - tempoBateuCartao >= tempoReset) {
    leituraEfetuada = false;
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, LOW);
    digitalWrite(ledVerde, LOW);
  }
  if(!acaoMQTT){
     //Aguarda até que um cartão seja encostado
    if ( ! rfid.PICC_IsNewCardPresent())
        return;
    //Aguarda até que um cartão seja lido
    if ( ! rfid.PICC_ReadCardSerial())
        return; 
  }
  //Caso nenhuma leitura tenha sido feita
  if (!leituraEfetuada||acaoMQTT) {
      digitalWrite(ledBranco, HIGH);
      if(acaoMQTT){
        cpfDocente=cpfAdmin;
        //Caso a porta esteja fechada, será aberta. Caso esteja aberta, será fechada.
        int posicao = fechadura.read();
        if(posicao==0){
          abrir();
        }
        else{
          fechar();
        }
      }
      else{
        modo_leitura();
        tempoBateuCartao = millis(); //Grava o tempo
        leituraEfetuada=true; //Registra que a leitura foi feita
        //Caso a porta esteja fechada, será aberta. Caso esteja aberta, será fechada.
        int posicao = fechadura.read();
        if(strcmp(cpfDocente.c_str(), cpfAdmin.c_str()) == 0){
          if(posicao == 0){
            fechadura.write(179);
          }
          else{
            fechadura.write(0);
          }
        }
        else{
           if(posicao==0){
              abrir();
            }
            else{
              fechar();
            }
        }
      }
  }
  //Caso a leitura já tenha sido feita
  else 
    Serial.println(F("Leitura já efetuada, aguardar tempo de reset."));
  //Para leitura momentaneamente
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}

bool connectMQTT() {
  client.setServer(mqtt_broker, mqtt_port);
  client.setCallback(callback);
  if (client.connect("CADEACHAVE_L21")) {
    client.publish(topic, "Dispositivo conectado");
    client.subscribe(topic);
    Serial.println("Conectado ao MQTT Broker!");
    return true;
  } else {
    Serial.print("Falha na conexão ao MQTT Broker, rc=");
    Serial.print(client.state());
    Serial.println(". Tentando novamente em 5 segundos");
    return false;
  }
}

bool reconnect() {
  Serial.print("Tentando reconectar ao MQTT Broker...");
  if (client.connect("CADEACHAVE_L21")) {
    Serial.println("Conectado ao MQTT Broker!");
    client.publish(topic, "Dispositivo reconectado");
    client.subscribe(topic);
  }
  return client.connected();
}

void callback(char *topic, byte *payload, unsigned int length) {
  Serial.print("Mensagem recebida no tópico: ");
  Serial.print(topic);
  Serial.print(". Mensagem: ");
  char msg[length + 1];
  strncpy(msg, (char *)payload, length);
  msg[length] = '\0';
  Serial.println(msg);
  if (strcmp(msg, "1") == 0) {
    acaoMQTT = true;
  }
}

//Função de requisição de abertura ou fechamento da porta
int fazerRequisicaoGet(String path, String token) {
  WiFiClientSecure client; // inicia cliente HTTPS
  String url=urlBase+path; //Concatena a url base com a informação de path
  Serial.println(url);
  //Obtem informações sobre o host e rota
  String host = url.substring(8);
  int index = host.indexOf('/');
  String rota = host.substring(index);
  host = host.substring(0, index);

  //Adiciona certificado SSL
  client.setFingerprint(fingerprint); 

  //Conecta ao host
  Serial.print("Conectando a ");
  Serial.println(host);
  if (!client.connect(host, 443)) {
    Serial.println("Falha na conexão");
    return -1;
  }

  //Envia requisição
  client.print(String("GET ") + rota + " HTTP/1.1\r\n" +
               "Host: " + host + "\r\n" +
               "Authorization: Bearer " + token + "\r\n" +
               "Connection: close\r\n\r\n");
  Serial.println("Requisição enviada");

  //Obtem código HTTP de resposta e retorna ao usuário
  while (client.connected()) {
    if (client.available()) {
      String line = client.readStringUntil('\n');
      if (line.startsWith("HTTP/1.1")) {
        int pos1 = line.indexOf(' ');
        int pos2 = line.indexOf(' ', pos1 + 1);
        int codigoHTTP = line.substring(pos1 + 1, pos2).toInt();
        client.stop();
        Serial.println(codigoHTTP);
        return codigoHTTP;
      }
    }
  }

  //Para o cliente
  client.stop();

  //Retorna -1 caso ocorra alguma falha de comunicação
  return -1;
}

//Função para obter token de autenticação
String fazerRequisicaoPost() {
  WiFiClientSecure client; //Inicia cliente

  //Obtem informações sobre o host e rota
  String host = urlAuth.substring(8);
  int index = host.indexOf('/');
  String rota = host.substring(index);
  host = host.substring(0, index);

  //Adiciona certificado SSL
  client.setFingerprint(fingerprint);

  //Conecta ao host
  Serial.print("Conectando a ");
  Serial.println(host);
  if (!client.connect(host, 443)) {
    Serial.println("Falha na conexão");
    return "";
  }

  //Envia requisição
  String json = "{ \"login\":\"" + login + "\", \"password\":\"" + senha + "\" }";
  client.print(String("POST ") + rota + " HTTP/1.1\r\n" +
               "Host: " + host + "\r\n" +
               "Content-Type: application/json\r\n" +
               "Content-Length: " + json.length() + "\r\n" +
               "Connection: close\r\n\r\n" +
               json);

  Serial.println("Requisição enviada");

  //Obtem informações de resposta
  String line;
  while (client.connected()) {
    line = client.readStringUntil('\n');
    if (line == "\r") {
      Serial.println("Cabeçalho recebido");
      break;
    }
  }
  while(client.available()){        
    line += client.readStringUntil('\n');
  }
  Serial.println("Corpo da resposta recebido");

  //Para o cliente
  client.stop();

  //Extrai apenas a token da resposta e a retorna
  String token = extrairToken(line);
  return token;
}

//Inicia conexão Wifi
void initWiFi() {
  delay(10);
  Serial.println("Conectando-se em: " + String(SSID));
  WiFi.begin(SSID, PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(100);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Conectado na Rede " + String(SSID) + " | IP => ");
  Serial.println(WiFi.localIP());
}

//Imprime ID do cartão RFID em hexadecimal
void printHex(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
      Serial.print(buffer[i] < 0x10 ? " 0" : " ");
      Serial.print(buffer[i], HEX);
  }
}

//Função de abertura da porta
void abrir(String cpf){
  //Obtem token de autenticação
  String token = fazerRequisicaoPost();
  if(token.equals("")){
    Serial.println("Falha ao obter token de autenticação");
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    cpfDocente="";
    acaoMQTT=false;
    return;
  }

  //Envia requisição de abertura
  int resposta;
  Serial.println("Enviando requisição para abrir.");
  Serial.println("");
  resposta = fazerRequisicaoGet("/abrir/"+nome+"/"+cpf,token);
  
  //Retorno por status
  if(resposta==200){
    fechadura.write(179);
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVerde, HIGH);
    Serial.println("Porta aberta");
  }
  else if (resposta==404){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Professor ou sala não encontrada");
  }
  else if (resposta==403){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Professor sem acesso a sala");
  }
   else if (resposta==409){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Sala já está aberta");
  }
   else {
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Falha na comunicação com o servidor");
  }
  cpfDocente="";
  acaoMQTT=false;
}

//Função de fechamento da porta
void fechar(String cpf){
  //Obtem token de autenticação
  String token = fazerRequisicaoPost();
  if(token.equals("")){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Falha ao obter token de autenticação");
    cpfDocente="";
    acaoMQTT=false;
    return;
  }

  //Envia requisição de fechamento
  int resposta;
  Serial.println("Enviando requisição para fechar.");
  Serial.println("");
  resposta = fazerRequisicaoGet("/fechar/"+nome+"/"+cpf,token);

  //Retorno por status
  if(resposta==200){
    fechadura.write(0);
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVerde, HIGH);
    Serial.println("Porta fechada");
  }
  else if (resposta==404){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Professor ou sala não encontrada");
  }
  else if (resposta==403){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Professor sem acesso a sala");
  }
   else if (resposta==409){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Sala já está fechada");
  }
  else if (resposta==401){
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Professor não foi o último a abrir");
  }
  else {
    digitalWrite(ledBranco, LOW);
    digitalWrite(ledVermelho, HIGH);
    Serial.println("Falha na comunicação com o servidor");
  }
  cpfDocente="";
  acaoMQTT=false;
}

//Função para extrair token da resposta
String extrairToken(String resposta) {
  Serial.println(resposta);
  int startPos = resposta.indexOf("{\"token") + 10;
  Serial.println(startPos);
  int endPos = resposta.indexOf("\",", startPos);
  Serial.println(endPos);
  String token = resposta.substring(startPos, endPos);
  Serial.println("Token extraído:");
  Serial.println(token);
  return token;
}

void modo_leitura()
{
  Serial.flush();
  //Mostra UID na serial
  Serial.print("UID da tag : ");
  String conteudo = "";
  byte letra;
  for (byte i = 0; i < rfid.uid.size; i++)
  {
    Serial.print(rfid.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(rfid.uid.uidByte[i], HEX);
    conteudo.concat(String(rfid.uid.uidByte[i]<0x10 ? " 0" : " "));
    conteudo.concat(String(rfid.uid.uidByte[i], HEX));
  }
  Serial.println();
 
  //Obtem os dados do setor 1, bloco 4 = Nome
  MFRC522::StatusCode status;
  byte buffer[30];
  byte size = sizeof(buffer);
 
  //Obtem os dados do setor 0, bloco 1 = Sobrenome
  byte  sector         = 0;
  byte blockAddr      = 1;
  byte trailerBlock   = 3;
 
  //Autenticacao usando chave A
  status=rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,
                                  trailerBlock, &key, &(rfid.uid));
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(rfid.GetStatusCodeName(status));
    return;
  }
  status = rfid.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(rfid.GetStatusCodeName(status));
  }
  //Mostra os dados do sobrenome no Serial Monitor e LCD
  
  aes128.decryptBlock(decryptedtext, buffer);

       Serial.println("\nTexto Descriptografado:");
for (int i = 0; i < sizeof(decryptedtext); i++) {
  Serial.write(decryptedtext[i]);
}
Serial.println();
Serial.flush();

cpfDocente = "";

  // Converter os bytes descriptografados em uma string
 for (int i = 0; i < sizeof(decryptedtext); i++) {
    // Adicionar cada byte à string cpfDocente
    // Utilize a função char() para converter o byte em um caractere
    cpfDocente += char(decryptedtext[i]);
  }

  // Remover quaisquer espaços extras que possam ter sido adicionados durante a conversão
  cpfDocente.trim();

  // Saída para monitor serial para verificação
  Serial.println("CPF do docente: " + cpfDocente);
   int tamanhoCpfDocente = cpfDocente.length();
  Serial.println("Tamanho do CPF do docente: " + String(tamanhoCpfDocente));

  
  delay(1000);
}
