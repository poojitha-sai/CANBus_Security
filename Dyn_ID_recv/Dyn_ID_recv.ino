#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include <string.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#include <mcp_can.h>
#include <SPI.h>

GCM<AES256> gcm;

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
uint8_t adata[16];



// the cs pin of the version after v1.1 is default to D9
// v0.9b and v1.0 is default D10
const int SPI_CS_PIN = 9;

MCP_CAN CAN(SPI_CS_PIN);                                    // Set CS pin

void setup()
{
  Serial.begin(9600);

  while (CAN_OK != CAN.begin(CAN_500KBPS))              // init can bus : baudrate = 500k
  {
    Serial.println("CAN BUS Shield init fail");
    Serial.println(" Init CAN BUS Shield again");
    delay(100);
  }
  Serial.println("CAN BUS Shield init ok!");
  gcm.setKey(key, sizeof(key));
  //  gcm.setIV(iv, sizeof(iv));
  gcm.addAuthData(adata, sizeof(adata));
}


void loop()
{

  uint8_t plaintext[Num_IDs][8];
  uint8_t tag[Num_IDs][8];
  uint8_t ciphertext[Num_IDs][16];
  bool auth_result[Num_IDs];
  uint8_t msgData[Num_IDs][8];
  uint8_t msgTag[Num_IDs][8];
  unsigned char len = 8;
  unsigned char buf[8];
  static uint8_t recv[Num_IDs];
  unsigned int canId;
  unsigned long RecvDelay[Num_IDs];
  bool enable[Num_IDs];

  if (CAN_MSGAVAIL == CAN.checkReceive())           // check if data coming
  {
    CAN.readMsgBuf(&len, buf);    // read data,  len: data length, buf: data buf

    canId = CAN.getCanId();

    /*
        Serial.println("-----------------------------");
        Serial.print("Get data from ID: ");
        Serial.println(canId, HEX);

        for (int i = 0; i < len; i++) // print the data
        {
          Serial.print(buf[i], HEX);
          Serial.print("\t");
        }
        Serial.println();
    */

    //Dyn switching
    /*Dynamic ID mirroring logic*/
    for (int i = 1; i <= Num_Clusters; i++)
    {
      for (int y = 1; y <= Num_Mirr; y++)
      {
        int z = 2 * Num_Mirr * (i - 1) + y - 1;
        int x = y + ((i - 1) * Num_Mirr) - 1;
        if (canId == z)
        {
          /*Start recv delay timer if Tag is received and set the enable to start delay measurement*/
//          if (enable[x] == 0)
//          {
//            RecvDelay[x] = micros();
//            enable[x] = 1;
//          }
          copy(buf, msgTag[x], 8);
          recv[x] |= 1;

        }
        else if (canId == (z + Num_Mirr))
        {
          /*Start recv delay timer if Msg is received and set the enable to start delay measurement*/
//          if (enable[x] == 0)
//          {
//            RecvDelay[x] = micros();
//            enable[x] = 1;
//          }
          copy(buf, msgData[x], 8);
          recv[x] |= 2;

        }


        if (recv[x] == 3) //to check if both tag and data are received.
        {
          for (uint8_t j = 0; j < 8; j++)
          {
            /*Copy data so that it is not lost*/
            ciphertext[x][j] = msgData[x][j];
            tag[x][j] = msgTag[x][j];

          }

          if (enable[x] == 0)
          {
            RecvDelay[x] = micros();
            enable[x] = 1;
          }
          /*GCM decryption*/
          gcm.setKey(key, sizeof(key));
          gcm.setIV(iv[x], sizeof(iv[x]));
          gcm.decrypt(plaintext[x], ciphertext[x], 8);
//          Serial.print((String)"plaintext[" + x + "]\n");
//          for (int j = 0; j < 8; j++) {
//            Serial.print(plaintext[x][j], DEC); //To plot data in MATLAB Simulink
//            Serial.println("");
//          }

          /*GCM authentication*/
          auth_result[x] = gcm.checkTag(tag[x], 8);
          
          RecvDelay[x] = micros() - RecvDelay[x];
          enable[x] = 0;
          Serial.println((String)"RecvDelay[" + x + "] =" + RecvDelay[x] + "\n" );
          
          if (auth_result[x] == 1)
          {
            Serial.println((String)"Message " + x + " authenticated");

          }
          /*Stop recv delay timer and reset the enable for next iteration*/
//          RecvDelay[x] = micros() - RecvDelay[x];
//          enable[x] = 0;
//          Serial.println((String)"RecvDelay[" + x + "] =" + RecvDelay[x] + "\n" );
          recv[x] = 0;
        }

      }
    }
  }

  //Dyn switching ends

}


void copy(uint8_t* src, uint8_t* dst, uint8_t len) {
  memcpy(dst, src, sizeof(src[0])*len);
}
