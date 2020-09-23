//#include <CryptoLegacy.h>

#include <Crypto.h>
//#include <CryptoLW.h>
#include <AES.h>
//#include <Speck.h>
//#include <SpeckTiny.h>
#include <GCM.h>
#include <string.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#include <mcp_can.h>
#include <SPI.h>

const int SPI_CS_PIN = 9;

MCP_CAN CAN(SPI_CS_PIN);                                    // Set CS

GCM<AES128> gcm;

/*Choose total number of IDs*/
const uint8_t Num_IDs = 6;
/*Choose total number of Clusters*/
const uint8_t Num_Clusters = 2;
/*Total number of IDs per cluster*/
uint8_t Num_Mirr = Num_IDs / Num_Clusters;
/*AES128 - 16 byte key*/
uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
/*AES128 - 16 byte IV for each ID*/
uint8_t iv[Num_IDs][16] = {{0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}, {1, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}, {2, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}, {3, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}, {4, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}};
uint8_t ciphertext[Num_IDs][16];
uint8_t tag[Num_IDs][8];

void setup() {


  // put your setup code here, to run once:
  Serial.begin(9600);

  //

  //CAN Bus init

  while (CAN_OK != CAN.begin(CAN_500KBPS))              // init can bus : baudrate = 500k
  {
    Serial.println("CAN BUS Shield init fail");
    Serial.println(" Init CAN BUS Shield again");
    delay(100);
  }
  Serial.println("CAN BUS Shield init ok!");

  //CAN BUS init end

  gcm.setKey(key, sizeof(key));
  //  gcm.setIV(iv, sizeof(iv));

}


void loop() {
  // put your main code here, to run repeatedly:

  /*8 byte Input for encryption*/
  uint8_t input[Num_IDs][8] = {{0, 0}, {0, 1, 2, 3, 0, 0, 0, 0}, {0, 1, 2, 3, 0, 0, 0, 0}, {0x0F, 11, 2, 0x3C, 0x11, 0xB3, 3, 13}, {0x0F, 11, 2, 0x3C, 0x11, 0xB3, 3, 13}};

  uint8_t adata[16];

  uint8_t plaintext[Num_IDs][8];

  bool auth_result[Num_IDs];
  unsigned long SendDelay[Num_IDs];
  bool enable[Num_IDs];

  /*Dynamic ID mirroring logic*/
  for (int i = 1; i <= Num_Clusters; i++)
  {
    for (int y = 1; y <= Num_Mirr; y++)
    {
      int z = 2 * Num_Mirr * (i - 1) + y - 1;
      int x = y + ((i - 1) * Num_Mirr) - 1;

      /*Start send delay timer*/
      if (enable[x] == 0)
      {
        SendDelay[x] = micros();
        enable[x] = 1;
      }

      //Dyn enc
      gcm.setKey(key, sizeof(key));
      gcm.setIV(iv[x], sizeof(iv[x]));
      gcm.encrypt(ciphertext[x], input[x], 8); //sizeof(input) = 8?
//      Serial.println((String)"ciphertext[" + x + "]\n");
//      for (int j = 0; j < 8; j++) {
//        Serial.print(ciphertext[x][j], DEC);
//        Serial.println("");
//      }
//      Serial.println("");
      gcm.computeTag(tag[x], 8);
//      Serial.println((String)"Tag[" + x + "]\n");
//      for (int j = 0; j < 8; j++) {
//        //  hmacbuf[i] = hmac[i];
//        Serial.print(tag[x][j], DEC);
//        Serial.println("");
//      }
      
      SendDelay[x] = micros() - SendDelay[x];
      Serial.println((String)"SendDelay[" + x + "] =" + SendDelay[x] + "\n" );
      enable[x] = 0;
      
      //Dyn enc end


      /*Decryption Part
            gcm.setKey(key, sizeof(key));
            gcm.setIV(iv, sizeof(iv));
            gcm.decrypt(plaintext[x], ciphertext[x], 8); //sizeof(input) = 8?
            Serial.print((String)"plaintext[" + x + "]");
            for (int j = 0; j < 8; j++) {
              Serial.print(plaintext[x][j], HEX);
              Serial.println("");
            }
            Serial.println("\n");

            auth_result[x] = gcm.checkTag(tag[x], 8);
            Serial.println((String)"auth_result[" + x + "]");
            Serial.print(auth_result[x]);
            Serial.println("");

            if (auth_result[x] == 1)
            {
              Serial.println((String)"Message "+ x +" authenticated");

            }
        Decryyption part ends*/

      CAN.sendMsgBuf(z, 0, 8, tag[x]);
      CAN.sendMsgBuf(z + Num_Mirr, 0, 8, ciphertext[x]);
      /*Stop send delay timer and reset the enable for next iteration*/
//      SendDelay[x] = micros() - SendDelay[x];
//      Serial.println((String)"SendDelay[" + x + "] =" + SendDelay[x] + "\n" );
//      enable[x] = 0;
    }
  }

}




void copy(uint8_t* src, uint8_t* dst, uint8_t len) {
  memcpy(dst, src, sizeof(src[0])*len);
}
