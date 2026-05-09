#include <Wire.h>
#include <Adafruit_PN532.h>

#define IRQ_PN532 (2)
#define RST_PN532 (3)

#define TIMEOUT 1000
#define PN532_EMSG "[-] Cannot init or setup PN532"

#define ZERO_BLOCK 0
#define BLOCK_SIZE 16
#define UID_LEN 4
#define JCOP41_OFFS 7

Adafruit_PN532 nfc(IRQ_PN532, RST_PN532);

bool is_jcop41(uint8_t* block_data) {
  return (block_data[0] == 0x6d && block_data[1] == 0x00 && block_data[2] == 0x7d && block_data[3] == 0x00 && block_data[4] == 0xff && block_data[5] == 0xff && block_data[6] == 0xff);
}

bool is_block_empty(uint8_t* block_data) {
  return (!block_data[0] && !block_data[1] && !block_data[2] && !block_data[3] && !block_data[4]);
}

void throw_error(const char* msg) {
  Serial.println(msg);

  while (1) {
    digitalWrite(2, HIGH);
    delay(300);
    digitalWrite(2, LOW);
    delay(300);
  }
}

void print_firmware_version(uint32_t version) {
  Serial.print("[i] Firmware version : ");
  Serial.print((version >> 16) & 0xff, DEC);
  Serial.print(".");
  Serial.print((version >> 8) & 0xff, DEC);
  Serial.println();
}

void print_mifare_uid(uint8_t* uid, uint8_t uid_len) {
  Serial.print("[+] Card detected. UID : ");

  for (uint8_t i = 0; i < uid_len; ++i) {
    if (uid[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(uid[i], HEX);
    Serial.print(" ");
  }

  Serial.println();
}

void print_mifare_block_data(uint8_t* block) {
  Serial.print("[+] Block data : ");

  for (uint8_t i = 0; i < BLOCK_SIZE; ++i) {
    if (block[i] < 0x10) {
      Serial.print("0");
    }

    Serial.print(block[i], HEX);
    Serial.print(" ");
  }

  Serial.println();
}

void copy(uint8_t* src, uint8_t* dst, uint8_t len) {
  for (uint8_t i = 0; i < len; ++i) {
    dst[i] = src[i];
  }
}

int8_t memcmp(uint8_t* arg1, uint8_t* arg2, uint8_t len) {
  for (uint8_t i = 0; i < len; ++i) {
    if (arg1[i] != arg2[i]) {
      return arg1[i] - arg2[i];
    }
  }

  return 0;
}

void setup() {
  Serial.begin(115200);
  pinMode(2, OUTPUT);

  if (nfc.begin() <= 0) {
    throw_error(PN532_EMSG);
  }

  uint32_t version = nfc.getFirmwareVersion();

  if (!version) {
    throw_error(PN532_EMSG);
  }

  Serial.println("[+] PN532 init");
  print_firmware_version(version);

  if (nfc.SAMConfig() <= 0) {
    throw_error(PN532_EMSG);
  }

  Serial.println();
}

uint8_t calculate_checksum(uint8_t* new_uid) {
  return new_uid[0] ^ new_uid[1] ^ new_uid[2] ^ new_uid[3];
}

void sleep() {
  while (1) {
    delay(5000);
  }
}

uint8_t key[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

uint8_t uid2clone[7] = {0, 0, 0, 0, 0, 0, 0};
uint8_t old_clone_uid[7] = {0, 0, 0, 0, 0, 0, 0};
uint8_t uid_len = 0;

uint8_t block_data[BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t old_clone_block_data[BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

bool card_found = false;
bool card_auth = false;
bool card_read = false;
bool card_write = false;

uint8_t uid_attemps = 100;
uint8_t auth_attemps = 10;
uint8_t read_write_attemps = 5;

void loop() {
  Serial.println("[i] Move card wich will be cloned\n");

  while (!card_found && uid_attemps) {
    card_found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid2clone, &uid_len, TIMEOUT);
    uid_attemps--;
  }

  if (!card_found) {
    Serial.println("[-] Card not found. Process finished. Reset ESP32 to restart");
    sleep();
  }

  digitalWrite(2, HIGH);
  delay(300);
  digitalWrite(2, LOW);

  print_mifare_uid(uid2clone, uid_len);

  while (!card_auth && auth_attemps) {
    card_auth = nfc.mifareclassic_AuthenticateBlock(uid2clone, uid_len, ZERO_BLOCK, MIFARE_CMD_AUTH_A, key);
    auth_attemps--;
  }

  if (card_auth) {
    Serial.println("[+] Card for cloning authentificated");

    while (!card_read && read_write_attemps) {
      card_read = nfc.mifareclassic_ReadDataBlock(ZERO_BLOCK, block_data);
      read_write_attemps--;
    }

    if (card_read) {
      Serial.println("[+] Card for cloning read");
      print_mifare_block_data(block_data);
    } else {
      Serial.println("[-] Cannot read data from card for cloning. Got only UID without full 0-block");
    }
  } else {
    Serial.println("[-] Cannot authentificate to card for cloning. Got only UID without full 0-block");
  }

  card_found = false;
  uid_attemps = 100;

  Serial.println();
  Serial.println("[i] Move card to rewrite 0-block\n");

  while (!card_found && uid_attemps) {
    card_found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, old_clone_uid, &uid_len, TIMEOUT);

    if (card_found && memcmp(uid2clone, old_clone_uid, UID_LEN) == 0) {
      card_found = false;
      continue;
    }

    uid_attemps--;
  }

  if (!card_found) {
    Serial.println("[-] Clone card not found. Process finished & UID of card for cloning dumped. Reset ESP32 to restart");
    sleep();
  }

  digitalWrite(2, HIGH);
  delay(300);
  digitalWrite(2, LOW);

  print_mifare_uid(old_clone_uid, uid_len);

  card_auth = false;
  auth_attemps = 10;

  while (!card_auth && auth_attemps) {
    card_auth = nfc.mifareclassic_AuthenticateBlock(old_clone_uid, uid_len, ZERO_BLOCK, MIFARE_CMD_AUTH_A, key);
    auth_attemps--;
  }

  if (card_auth) {
    Serial.println("[+] Clone-card authentificated");

    card_read = false;
    read_write_attemps = 5;

    while (!card_read && read_write_attemps) {
      card_read = nfc.mifareclassic_ReadDataBlock(ZERO_BLOCK, old_clone_block_data);
      read_write_attemps--;
    }

    if (card_read) {
      Serial.println("[+] Clone card read");
      print_mifare_block_data(old_clone_block_data);
    } else {
      Serial.println("[-] Cannot read data from clone card");
    }

    if (is_block_empty(block_data) || is_jcop41(block_data)) {
      copy(uid2clone, block_data, UID_LEN);
      block_data[4] = calculate_checksum(uid2clone);
      copy(old_clone_block_data + 5, block_data + 5, BLOCK_SIZE - 5);
    } 

    read_write_attemps = 5;

    while (!card_write && read_write_attemps) {
      card_write = nfc.mifareclassic_WriteDataBlock(ZERO_BLOCK, block_data);
      read_write_attemps--;
    }

    if (card_write) {
      print_mifare_block_data(block_data);

      card_found = false;

      while (!card_found) {
        card_found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, old_clone_uid, &uid_len, TIMEOUT);
      }

      Serial.println();

      if (memcmp(uid2clone, old_clone_uid, UID_LEN) == 0) {
        Serial.println("[+] Card cloned successfully. Process finished. Reset ESP32 to restart");
      } else {
        goto nope;
      }
    } else {
      nope: Serial.println("[-] Cannot clone card. Process finished. Reset ESP32 to restart");
    }
    sleep();
  } else {
    Serial.println("[-] Cannot authentificate clone-card. Process finished. Reset ESP32 to restart");
    sleep();
  }
}
