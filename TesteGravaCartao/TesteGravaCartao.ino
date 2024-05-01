#include <CryptoAES_CBC.h>
#include <AES.h>
#include <string.h>

// Chave de 16 bytes (128 bits) para criptografia
byte chave[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
// Armazena o texto criptografado
byte cypher[16];
// Armazena o texto descriptografado após a decodificação
byte decryptedtext[16];
// Objeto da classe AES128
AES128 aes128;

int index = 0;
bool textComplete = false;
 
#include <SPI.h>
#include <MFRC522.h>
 
//Pinos Reset e SS módulo MFRC522
#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);
 
MFRC522::MIFARE_Key key;
 
void setup()
{
  Serial.begin(9600);   //Inicia a serial
  SPI.begin();      //Inicia  SPI bus
  mfrc522.PCD_Init();   //Inicia MFRC522
 
  //Prepara chave - padrao de fabrica = FFFFFFFFFFFFh
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;
  aes128.setKey(chave, 16); // Define a chave para AES
}
 
void loop()
{
  
    Serial.println("Modo gravacao");
    modo_gravacao();
}
 
void mensagem_inicial_cartao()
{
  Serial.println("Aproxime o seu cartao do leitor...");
}
 
void modo_leitura()
{
  Serial.flush();
  //Aguarda cartao
  while ( ! mfrc522.PICC_IsNewCardPresent())
  {
    delay(100);
  }
  if ( ! mfrc522.PICC_ReadCardSerial())
  {
    return;
  }
  //Mostra UID na serial
  Serial.print("UID da tag : ");
  String conteudo = "";
  byte letra;
  for (byte i = 0; i < mfrc522.uid.size; i++)
  {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
    conteudo.concat(String(mfrc522.uid.uidByte[i]<0x10 ? " 0" : " "));
    conteudo.concat(String(mfrc522.uid.uidByte[i], HEX));
  }
  Serial.println();
 
  //Obtem os dados do setor 1, bloco 4 = Nome
  byte status;
  byte buffer[30];
  byte size = sizeof(buffer);
 
  //Obtem os dados do setor 0, bloco 1 = Sobrenome
  byte  sector         = 0;
  byte blockAddr      = 1;
  byte trailerBlock   = 3;
 
  //Autenticacao usando chave A
  status=mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,
                                  trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  status = mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  //Mostra os dados do sobrenome no Serial Monitor e LCD
  
  aes128.decryptBlock(decryptedtext, buffer);

       Serial.println("\nTexto Descriptografado:");
for (int i = 0; i < sizeof(decryptedtext); i++) {
  Serial.write(decryptedtext[i]);
}
Serial.println();
Serial.flush();
 
  delay(3000);
}
 
void modo_gravacao()
{
  mensagem_inicial_cartao();
  modo_leitura();
  //Mostra o tipo do cartao
  Serial.print(F("Tipo do PICC: "));
  byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
 
  byte buffer[16];
  byte block;
  byte status, len;
  for (byte i = 0; i < 16; i++) {
    buffer[i] = ' ';
  }
 
  Serial.setTimeout(20000L) ;
  Serial.println(F("Digite o CPF,em seguida o caractere #"));
  Serial.flush();
  len = Serial.readBytesUntil('#', (char *) buffer, 16) ;
  Serial.println(len);
  
 byte index = -1;
for (byte i = 0; i < len; i++) {
    if (buffer[i] != '\n' && buffer[i] != ' '&& buffer[i] !='\r') {
        buffer[++index] = buffer[i];
    }
}
  
  // Preenche o restante do buffer com espaços em branco, se necessário
  for (byte i = 11; i < 16; i++) {
    buffer[i] = ' ';
  }
  aes128.encryptBlock(cypher, buffer);
 
  block = 1;
  //Serial.println(F("Autenticacao usando chave A..."));
  status=mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,
                                    block, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
 
  //Grava no bloco 1
  status = mfrc522.MIFARE_Write(block, cypher, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    Serial.println(F("Dados gravados com sucesso!"));
  }
 
  mfrc522.PICC_HaltA(); // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
  delay(5000);
}
