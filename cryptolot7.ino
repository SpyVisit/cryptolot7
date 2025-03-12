#include <uECC.h>
#include <Arduino.h>
#include <SHA256.h>
#include "ripemd160.h"
#define LED_PIN_RED D13  // Определяем пин, к которому подключен светодиод
#define LED_PIN_YELLOW D12  // Определяем пин, к которому подключен светодиод
#define LED_PIN_GREEN D11  // Определяем пин, к которому подключен светодиод

// Функция генерации случайного приватного ключа (32 байта)
void generatePrivateKey(uint8_t *privateKey) {
  for (int i = 0; i < 32; i++) {
    // Используем диапазон от 1 до 255, чтобы избежать нулевых байтов
    privateKey[i] = random(1, 256);
  }
}

// Функция вычисления публичного ключа из приватного (нежатый формат: 65 байт)
// Возвращает true, если ключ успешно вычислен.
bool getPublicKey(const uint8_t *privateKey, uint8_t *publicKey) {
  const struct uECC_Curve_t *curve = uECC_secp256k1();
  uint8_t temp[64];  // временный буфер для 64-байтного ключа
  if (!uECC_compute_public_key(privateKey, temp, curve)) {
    return false;
  }
  publicKey[0] = 0x04;              // добавляем префикс для нежатого формата
  memcpy(publicKey + 1, temp, 64);  // копируем координаты X и Y
  return true;
}
//===================================================================================
// реализация Публичный ключ хешируется (SHA-256 + RIPEMD-160) для получения биткоин-адреса.
// Функция для преобразования одного шестнадцатеричного символа в число
uint8_t hexCharToByte(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0;
}

// Преобразует шестнадцатеричную строку в массив байт
void hexStringToBytes(String hex, uint8_t *bytes, int byteCount) {
  for (int i = 0; i < byteCount; i++) {
    bytes[i] = (hexCharToByte(hex.charAt(i * 2)) << 4) | hexCharToByte(hex.charAt(i * 2 + 1));
  }
}

// Функция Base58-кодирования (реализация, подходящая для небольших массивов)
String Base58Encode(const uint8_t* input, int len) {
  // Алфавит Base58 (без 0, O, I, l)
  const char* ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  // Подсчёт ведущих нулей
  int zeros = 0;
  while (zeros < len && input[zeros] == 0) {
    zeros++;
  }

  // Оценка максимальной длины результата
  int size = (len - zeros) * 138 / 100 + 1;
  uint8_t b58[size];
  memset(b58, 0, size);

  // Перевод входных данных в систему с основанием 58
  for (int i = zeros; i < len; i++) {
    int carry = input[i];
    for (int j = size - 1; j >= 0; j--) {
      carry += 256 * b58[j];
      b58[j] = carry % 58;
      carry /= 58;
    }
  }

  // Пропуск лидирующих нулей в массиве b58
  int it = 0;
  while (it < size && b58[it] == 0) {
    it++;
  }

  // Формирование строки результата: каждому входному нулю соответствует символ '1'
  String result = "";
  for (int i = 0; i < zeros; i++) {
    result += '1';
  }
  for (; it < size; it++) {
    result += ALPHABET[b58[it]];
  }
  return result;
}

// Функция, принимающая публичный ключ в виде шестнадцатеричной строки
// и возвращающая биткоин-адрес (Base58)
String publicKeyToBitcoinAddress(String pubKeyHex) {
  // Шаг 1: Преобразование шестнадцатеричной строки в бинарный массив
  int pubKeyLen = pubKeyHex.length();
  int byteLen = pubKeyLen / 2;
  uint8_t pubKeyBytes[byteLen];
  hexStringToBytes(pubKeyHex, pubKeyBytes, byteLen);

  // Шаг 2: Вычисление SHA-256 от публичного ключа
  uint8_t sha256Hash[32];
  SHA256 sha256;
  sha256.reset();
  sha256.update(pubKeyBytes, byteLen);
  sha256.finalize(sha256Hash, 32);

  // Шаг 3: Вычисление RIPEMD-160 от результата SHA-256
  uint8_t ripemdHash[20];
  CRIPEMD160 ripemd160;
  ripemd160.Reset();
  ripemd160.Write(sha256Hash, 32);
  ripemd160.Finalize(ripemdHash);

  // Шаг 4: Добавление версии (0x00 для основного блокчейна Bitcoin)
  uint8_t extendedRipemd[21];
  extendedRipemd[0] = 0x00;
  memcpy(extendedRipemd + 1, ripemdHash, 20);

  // Шаг 5: Вычисление контрольной суммы (double SHA-256, первые 4 байта)
  uint8_t checksum1[32];
  sha256.reset();
  sha256.update(extendedRipemd, 21);
  sha256.finalize(checksum1, 32);

  uint8_t checksum2[32];
  sha256.reset();
  sha256.update(checksum1, 32);
  sha256.finalize(checksum2, 32);

  uint8_t checksum[4];
  memcpy(checksum, checksum2, 4);

  // Шаг 6: Формирование 25-байтного массива (extendedRipemd + контрольная сумма)
  uint8_t binaryAddress[25];
  memcpy(binaryAddress, extendedRipemd, 21);
  memcpy(binaryAddress + 21, checksum, 4);

  // Шаг 7: Base58-кодирование полученного массива
  String bitcoinAddress = Base58Encode(binaryAddress, 25);
  return bitcoinAddress;
}

// конец реализации Публичный ключ хешируется (SHA-256 + RIPEMD-160) для получения биткоин-адреса.
//====================================================================================
// Функция лотерейного поиска

// Структура для хранения пары "адрес - число"
struct BitcoinEntry {
  const char *address;
  int value;
};

// Массив с данными (при необходимости список можно изменять)
const BitcoinEntry bitcoinList[] = {
{"1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF", 79957}, 
{"1LdRcdxfbSnmCYYNdeYpUnztiYzVfBEQeC", 53880}, 
{"1AC4fMwgY8j9onSbXEWeH6Zan8QGMSdmtA", 51830}, 
{"1LruNZjwamWJXThX2Y8C2d47QqhAkkc5os", 44000}, 
{"12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr", 31000}, 
{"12tkqA9xSoowkzoERHMWNKsTey55YEBqkv", 28151}, 
{"17rm2dvb439dZqyMe2d4D6AQJSgg6yeNRn", 20008}, 
{"1PeizMg76Cf96nUQrYg8xuoZWLQozU5zGW", 19414}, 
{"1GR9qNz7zgtaW5HwwVpEJWMnGWhsbsieCG", 15746}, 
{"1F34duy2eeMz5mSrvFepVzy7Y1rBsnAyWC", 10771}, 
{"1f1miYFQWTzdLiCBxtHHnNiW7WAWPUccr", 10009}, 
{"1BAFWQhH9pNkz3mZDQ1tWrtKkSHVCkc3fV", 10000}, 
{"14YK4mzJGo5NKkNnmVJeuEAQftLt795Gec", 10000}, 
{"1Ki3WTEEqTLPNsN5cGTsMkL2sJ4m5mdCXT", 10000}, 
{"1KbrSKrT3GeEruTuuYYUSQ35JwKbrAWJYm", 10000}, 
{"1P1iThxBH542Gmk1kZNXyji4E4iwpvSbrt", 10000}, 
{"12tLs9c9RsALt4ockxa1hB4iTCTSmxj2me", 10000}, 
{"1ucXXZQSEf4zny2HRwAQKtVpkLPTUKRtt", 10000}, 
{"1CPaziTqeEixPoSFtJxu74uDGbpEAotZom", 10000}, 
{"1DcT5Wij5tfb3oVViF8mA8p4WrG98ahZPT", 10000}, 
{"1JQULE6yHr9UaitLr4wahTwJN7DaMX7W1Z", 10000}, 
{"1CY7fykRLWXeSbKB885Kr4KjQxmDdvW923", 10000}, 
{"1P9fAFAsSLRmMu2P7wZ5CXDPRfLSWTy9N8", 9425}, 
{"1HLvaTs3zR3oev9ya7Pzp3GB9Gqfg6XYJT", 9260}, 
{"167ZWTT8n6s4ya8cGjqNNQjDwDGY31vmHg", 8999}, 
{"18zuLTKQnLjp987LdxuYvjekYnNAvXif2b", 8021}, 
{"3PWn1AGqo8HWH8mXSsxx1Ytk87zMAAziFU", 8000}, 
{"198aMn6ZYAczwrE5NvNTUMyJ5qkfy4g3Hi", 8000}, 
{"15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX", 7941}, 
{"13eEt6myAo1zAC7o7RK5sVxxCNCAgd6ApH", 7000}, 
{"1DzjE3ANaKLasY2n6e5ToJ4CQCXrvDvwsf", 7000}, 
{"324rP14bzX8kW1JWt1J8ohZjDFyt2G68Kq", 7000}, 
{"1FJuzzQFVMbiMGw6JtcXefdD64amy7mSCF", 6999}, 
{"1Ac2JdpQ5c9NeSajdGx6dofxeXkn4S35ft", 6878}, 
{"1AYLzYN7SGu5FQLBTADBzqKm4b6Udt6Bw6", 6512}, 
{"1JxmKkNK1b3p7r8DDPtnNmGeLZDcgPadJb", 6316}, 
{"1LBBmkr9muf7RjjBbzQQvzNQpRRaVEnavs", 6200}, 
{"16rF2zwSJ9goQ9fZfYoti5LsUqqegb5RnA", 6101}, 
{"1J3B2ucUpWjWPPpejUCoLN93Gwz3q65CTd", 6000}, 
{"1MbNM3jwxMjRzeA9xyHbMyePN68MY4Jxb", 6000}, 
{"1FY6RL8Ju9b6CGsHTK68yYEcnzUasufyCe", 6000}, 
{"178E8tYZ5WJ6PpADdpmmZd67Se7uPhJCLX", 6000}, 
{"1BsdDaJtgFZrLfzEXvh6cD4VhtHHSHhMea", 6000}, 
{"1Lj2mCPJYbbC2X6oYwV6sXnE8CZ4heK5UD", 6000}, 
{"138EMxwMtKuvCEUtm4qUfT2x344TSReyiT", 5908}, 
{"13n67sFKgqLDKp8gx8Xvm6scdfY4ZeaU8p", 5700}, 
{"1DR93bfKVCUJkDvPuxbUAEtzYRaJEnwjNt", 5600}, 
{"1CCqLR8YrUMPFgYZWwLW8FkezbFjfeXD8n", 5595}, 
{"1BeouDc6jtHpitvPz3gR3LQnBGb7dKRrtC", 5075}, 
{"1ARWCREnmdKyHgNg2c9qih8UzRr4MMQEQS", 5000}, 
{"1DaCQDfStUgkPQXcf53Teeo6LPiKcVMBM9", 5000}, 
{"16Jka2DrvEGGJ6ks2kXRpxmQZLQmAFRoGk", 5000}, 
{"19z6WynrjHeD5MMv6919BuQRwybuen1sRv", 5000}, 
{"1NQEV6T4avmPqUVTvgsKkeB6yc8qnSWfhR", 5000}, 
{"1NJQZhzYac89fDhQCmb1khdjekKNVYLFMY", 5000}, 
{"12ytiN9oWQTRGb6JjZiaoWMAvF9nPWdGX1", 5000}, 
{"1Btud1pqADgGzgBCZzxzc2b1o1ytk1HYWC", 4900}, 
{"1BXZng4dcXDnYNRXRgHqWjzT5RwxHHBSHo", 4900}, 
{"1BvNwfxEQwZNRmYQ3eno6e976XyxhCsRXj", 4881}, 
{"17spLhCpZVdQXFz2ZL1aP5gRci6RFVNhrD", 4817}, 
{"1Miy5sJZSamDZN6xcJJidp9zYxhSrpDeJm", 4792}, 
{"1Kq6hXXiSpdp9bg9hDDyqm8ZfvgZmzchjn", 4699}, 
{"3Pv6S8ZEcQLmXigA694aUZhVmnLUjNzxcc", 4600}, 
{"16aEn4p6hK4FMpLtJGpoQZMZ946sDg1Z6n", 4503}, 
{"1MLiPwYjNACQHREFKwGtkPpWgd8PqpbuQ4", 4487}, 
{"18Hp8j2JMvwtPs1eqNaYEEVvuFpjQJRFVY", 4333}, 
{"16eb495TbiCRbRbZv4WBdaUvNGxUYJ4jed", 4322}, 
{"1JCrPqogEKEpM9fuFQV7LpF9e8cgf3YZ8m", 4251}, 
{"124YoiaSaUssbBeP5RukbSN9Evc3UJfwPj", 4154}, 
{"1GX7i8jG8DD1mG85BNnz7xybVhSmw84Uii", 4109}, 
{"1N5NqDWiLVqtU8mEzCNEeEbQVHwuGGChJs", 4049}, 
{"1VeMPNgEtQGurwjW2WsYXQaw4boAX5k6S", 4000}, 
{"18eY9oWL2mkXCL1VVwPme2NMmAVhX6EfyM", 4000}, 
{"1ALXLVNj7yKRU2Yki3K3yQGB5TBPof7jyo", 4000}, 
{"1LwBdypLh3WPawK1WUqGZXgs4V8neHHqb7", 4000}, 
{"1MPsPzkBK3w8J6CJyAFUkoiSaxTqWRabsk", 4000}, 
{"1HJDQbLauXEkzsTujzw5PaAqbcDCBeLiq1", 4000}, 
{"1DWB2HajYBcDBuB2iSGzRVaCpcQKEPvCsj", 3997}, 
{"15MZvKjqeNz4AVz2QrHumQcRJq2JVHjFUz", 3963}, 
{"1GMFSWQQQhCQyRNQcac9tDKcvqYCuripVs", 3674}, 
{"14mPMrRm6TdjqHZhd7aBUbuWt5MYWReukR", 3600}, 
{"1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx", 3350}, 
{"1Gn1GzVa88T1X3fdhejyq6jrZs43T24xW6", 3249}, 
{"1PTYXwamXXgQoAhDbmUf98rY2Pg1pYXhin", 3233}, 
{"16oKJMcUZkDbq2tXDr9Fm2HwgBAkJPquyU", 3215}, 
{"193zge613zys7eSkQYQVd9xubovLN8Sr6j", 3145}, 
{"1L9ipUywwErf9EaKCgLqrkoSM5ab3wrjvh", 3141}, 
{"1EgH7EUfgjr8gAK9t1BeHLDC1ijrVvdec3", 3082}, 
{"18jGeboNHt1YpsDFcCeYPKm8qnAe9942BG", 3069}, 
{"19HhmfxGsznL8K7wXjZiFnhqddQucgfZzB", 3000}, 
{"15DtovKcGFiAJmyVfbjvCXHyjtyoZhyyj4", 3000}, 
{"1ArZGb5V24gAgN51FeQknobi6kNyGx739r", 3000}, 
{"1JjMoB212ctAiuDvURyWhs813yY4c75cap", 3000}, 
{"1FDVbVJYKkWPFcJEzCxi99vpKTYxEY3zdj", 3000}, 
{"1Hc4EvgZmWECnETeTL4w4ySz76JxubyRjw", 3000}, 
{"1DVTB9YKi4KNjyEbAHPp17T8R1Pp17nSmA", 3000}, 
{"1MBPNZb1Rakm8hYaP9VGqUU6gyJQUod61y", 3000}, 
{"1GUNPhjykrBdET5sauhahRoN6Xb9pACs5j", 3000}, 
{"14kHu26yWkVD8qAnBfcFXHXxgquNoSpKum", 3000}, 
{"1AumBaQDRaCC3cKKQVRHeyvoSPWNdDzsKP", 3000}, 
{"1DnHx95d2t5URq2SYvVk6kxGryvTEbTnTs", 3000}, 
{"3J7Hkgtoqgpurrf4VjLyVovCjTRLxkfEYX", 3000}, 
{"1M6E6vPaYsuCb34mDNS2aepu2aJyL6xBG4", 3000}, 
{"18QUDxjDZAqAJorr4jkSEWHUDGLBF9uRCc", 3000}, 
{"13rCGm4Z3PDeYwo5a7GTT4jFYnRFBZbKr1", 3000}, 
{"15Exz1BAVan4Eweagy1rcPJnfyc6KJ4GvL", 3000}, 
{"1CE8chGD6Nu8qjcDF2uR1wMKyoWb8Kyxwz", 3000}, 
{"1FfgXrQUjX5nQ4zsiLBWjvFwW61jQHCqn", 3000}, 
{"13jTtHxBPFwZkaCdm6BwJMMJkqvTpBZccw", 3000}, 
{"1FTgXfXZRxMQcKSNeuFvWYVPsNgurTJ7BZ", 3000}, 
{"162z6mSSHzfTqb2Sn3NUk5r1Y2oGoCMCoM", 3000}, 
{"1AGAvShyB22eUxz1DKfBBgGENDSZP8dcq9", 3000}, 
{"1KpwMa1w9DTUCB5asCgUdLRA22hto1Qgqv", 2999}, 
{"1LQaq7LLoyjdfH3vczuusa17WsRokhsRvG", 2966}, 
{"1HoDPH3wCSCiyGmSXX7xiadW2DayqaNaCo", 2965}, 
{"167mYVwJA9bbZowuZ3Naadc68HT79eQL6B", 2959}, 
{"15HiQkbvQMoAzXyKdQbuCKTGDxTswYBUf5", 2939}, 
{"1AenFm1zSRkhtPHwZmP2UuRQbWpakD8cVZ", 2918}, 
{"1NY5KheH3koPcuQrBLXVGq87YbijtXdZXD", 2819}, 
{"13KYdPnzGh5H8exFY3FhUo9Rvvs6kKAcL8", 2800}, 
{"1EUJKGm3FB65rr5W9anAEoWA3m71WpDayZ", 2745}, 
{"38gTej4KSrED7Ds9wTHJegErQSmSbF1Qfx", 2669}, 
{"18cKGtwdQHmnDXD6w6AhBhHsmxnK8gsVHf", 2645}, 
{"19DdkMxutkLGY67REFPLu51imfxG9CUJLD", 2616}, 
{"1BrSzBwx2RLuppgGziqgF7oMuneHQVhsNc", 2600}, 
{"17j45BXWrjSDttuurcSQubYLdLescJ7eJH", 2585}, 
{"1BiYAPzckv6gosDRRK7tAX3TYU68Ah7vTF", 2578}, 
{"1AjbEPKeyW4MCUpwb37Y1HR9uDQso67mQx", 2510}, 
{"1P6brDbYKsQGqRduaTMa1v8hBqJYjig4Qc", 2510}, 
{"1NT1jtYLNwFXLztD4U4B9sLizdYatirhWW", 2500}, 
{"12owkvCcMPw5u1M692GbBFmpaMdX3kqXQM", 2500}, 
{"1Kj6epyY2MdzZUCHE572jeV9n7DDRReaZJ", 2407}, 
{"1Q6VMUacupsVvGgSW8puCdSb65jMVpSunQ", 2369}, 
{"1w7TJ4AJUpnRVAFdAKfngXVEyDHRbj6Nb", 2363}, 
{"152p1VPp2UYceP9BLtJRLoMgoErQRCryTt", 2350}, 
{"1NWPS2fWw6FMeJEjg6DMMpYxQyB4TKpVsb", 2343}, 
{"1CtHkU1vMbyvuxxX2ab72y2Bm566pY1du5", 2318}, 
{"1Dp1yVTFmgb6oL5WoNVsLsZso4ATMzxD1M", 2288}, 
{"12LGtnusgHL3FWN26SRc9WpAGrWxNptrCK", 2268}, 
{"1GbkwjPrrxdXB8ddewK3KhhCXgj8uZ2Y5K", 2255}, 
{"1HjdiADVHew97yM8z4Vqs4iPwMyQHkkuhj", 2200}, 
{"1G2ozMay5PggBFMvXtFDFiXk63u2XAMsqM", 2200}, 
{"35ysWwjZRokHuHbDWVZnd1HA9hs6YQtHLS", 2200}, 
{"1LoSbcBntvcFtVAERaYTDhPB62EGkchMRQ", 2200}, 
{"1JaPNwMXt2AuVkWmkUHbsw78MbGorTfmm2", 2195}, 
{"1CounterpartyXXXXXXXXXXXXXXXUWLpVr", 2131}, 
{"1VLZtmKa95BFrXHeyHEETAivJ22pTEhrT", 2100}, 
{"1NB3ZXxs3vfq1hRhuSAZ3zPdQNrXBQB6ZX", 2100}, 
{"13DyBwhpDw6152q1drbK2US5S3CdY1mRnU", 2100}, 
{"16Q5zhKCMbpEkR43K6tgzdkh1mTUfi7SMy", 2100}, 
{"13ACvVSUKeQ57zBtENsJtHManPTJ5sZuRw", 2100}, 
{"1MEKbMf7hPw2scP468unqAXjedZWMM4La4", 2097}, 
{"1MUsbRLywcuL9was1ahKd92nWqbwh7o4M2", 2085}, 
{"142fFLWkLgteEB48wC6tcChK5dXkptbjn6", 2068}, 
{"1CkdZXJtpbxxX4QAzbRhiFNU3PkcsUsFzw", 2066}, 
{"1CU33fX35WYJDNxXM5jqawQtVGr32QEGrV", 2050}, 
{"1BMB272EM8F9RXaFszJ7nxxN8VNjoa3mYu", 2012}, 
{"1MTq53R9mvrJomvHoq8i4uyLv26mWHhNPc", 2001}, 
{"13dSnmhFeX3qqbsi4thXXad4ggTh6VCESG", 2000}, 
{"16w8WZ8Ub1Whk6SP4cw4op5cgyRVsb77T8", 2000}, 
{"16y2tVCgnwGM6c3kPPuQDJrSadQqcddUm6", 2000}, 
{"18KHS8ndbKJ1iEtTxv44Ree3Fs7oCURg83", 2000}, 
{"1KF8CrJXpAf8EB63a91EHaH1TobnDsRgaK", 2000}, 
{"1NTva3cWy3Xiueh5GPWCa9cz8SePrv6cmT", 2000}, 
{"13RwLs69Y7xPrTM5E2aa9RxiDSyeX6jEyw", 2000}, 
{"1CSr9n9YMfrGFCQSMU3fBWyP9XcJSag8VF", 2000}, 
{"1KxQJau7BkuwHZh7Ugo2yoqKN9WeS51S5C", 2000}, 
{"1AsgPtK6qG5M8bHxcgeVzot12gfKnUnPW9", 2000}, 
{"14jNu8EmWnCB6C75gsQd4noYdt5gxqmnzo", 2000}, 
{"3KUoG9NjZP6AuxkAXAp5Y6JpdQzF6QGnD5", 2000}, 
{"1CqMbvPpLS8mWerAHiJSS9yasZaQ9bEsZf", 2000}, 
{"37ZP1W5fMeHWNFSmqTLV3Zin91tYPzbpbf", 2000}, 
{"324ezXhZPcFR9WCPpZ52FM6UWKpD8YxJNY", 2000}, 
{"3FXLxsjdt1BicD6Pzm5JcYji6Lvdv5VLbQ", 2000}, 
{"37qpUn6vNhezAiNN5193jJu1Kiv2ZBT6qj", 2000}, 
{"16maYEFESxYegRrDrm8AzmhYtGdHwHnvnx", 2000}, 
{"12KkxkrPeSR9H1SnbKT2UPepLgarz3tGHp", 1986}, 
{"1ER3nEZFqXUkKw6AucHnmPxXnQQ8F6SJEG", 1969}, 
{"14CQ2jCrpsd1eSdC4zWsJZH9LvDr6GrCyo", 1958}, 
{"3KhMqRMh3cLJCqZPdvJMx55h7onRWaJdit", 1936}, 
{"19rvEojniQQYqf4vGsvhPfiLMeYrag4gEe", 1925}, 
{"1C4H9GDALbjDVnbfTt4a9ML1XbwzLS1rUC", 1908}, 
{"1NPxp8rXDP1VhbjTwHNkXZyrqXeayzMDA4", 1879}, 
{"15HDbh92juxL9NRW4sm8wo3hmDoc32vWNM", 1861}, 
{"1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY", 1804}, 
{"1ctwnbd2GpxzNFZWyipXhPMWHM5pUB4Er", 1803}, 
{"13HVZCHH6ndYPGYLtwdk7bH5Bv2wGzv2wK", 1801}, 
{"15vwE15F9Umu3aigWfFx7XKHQqVS6TyoZo", 1800}, 
{"1Ek9Jj3Z3Bnipe3DnMq2otXG5iNjze66VR", 1799}, 
{"36USu4FE9kUEreVWHBtXotudq3VWrbF5uM", 1780}, 
{"1Go1p98x7EpKmEFiYnr4qjX6PJyxdfweJV", 1769}, 
{"1DtFKiPdYD2U6XDZGtWK7q8JYVrDKBHBqE", 1766}, 
{"13FKHnREotr4jrjiSJwPUpecogVT7Rj7bu", 1750}, 
{"15e8jdh1wKf3toj7yQWwuGNdMYyb6DTWE9", 1724}, 
{"12Eqq2YuTU5q5F7L1khsqMYzFfeU4xmjD2", 1700}, 
{"1BVMFfPXJy2TY1x6wm8gow3N5Amw4Etm5h", 1698}, 
{"3BjNP5gL661VmHxyw7JKUok1yGtdFenxy2", 1666}, 
{"159yDxnqLTjvUyoxxxJ5ZQ9LPXtGhGvbH5", 1665}, 
{"1HDNfSr5ExyGfe77GX681PPZtN2deoewfd", 1662}, 
{"162W4Sv2kJzLuzuQ52nF2oXTyfWYMH4Pxw", 1640}, 
{"113324vM6NBar2q72w6iDCdQvPnPQw8Tvw", 1600}, 
{"1MmcSBpzNYeGgSfVNxXEoBdpmsCxyMUuWW", 1600}, 
{"3EPqytXCCcapxe8dy6yufzLm1LXX8xmaLM", 1594}, 
{"1JNamaC2PE4woAk1vaoW46e5pxgdQkaKnc", 1592}, 
{"113fiz1m5ofgDnPueDXRXqyDMa8J3EirWZ", 1586}, 
{"1QEVCmvKS8KB3b5qo1JoYjMzMKxHWPast6", 1566}, 
{"1JN8QEWaBxSdo7jMaB9ywgfLEufAw56ezX", 1566}, 
{"bc1q0q6rshyllhwj6r9808meqcjl44c9rj7y7jzf62", 1565}, 
{"1JqJHk69j15VAHdxUDD4hFPW8acZKoFGdS", 1558}, 
{"1QEqQWSzrZfWsJ5Kxgh6BYnGJRjkYwMRmp", 1545}, 
{"1JKkR1fSQKY6qUGHdNrD9wzTavButq7AWp", 1526}, 
{"1J3St3rp3hVsuLGhegbLWicyPL3NRD3YJ7", 1523}, 
{"1khexYoq6fvMdKAww7dpdZb4WBPKBq2hb", 1518}, 
{"1F4N1oMNXJJRF33qcYkk58tZbEhGNH8NXN", 1501}, 
{"38fW4PLwRLqWKHWgE6R2i7k2P9jyACvKUc", 1501}, 
{"3Dq1AfreNRssqJ3uwvudULVKhaFL2hSLqU", 1501}, 
{"1PzfwiEeLJzXHjCJXNRwDaKiDoj9sGE1sp", 1500}, 
{"13oRbW4P5kYaSX4UXAyd5VsSYr8x5hX2Pv", 1500}, 
{"174NVbudzKV1jZnZvRzKvauZxnq25NfG4v", 1500}, 
{"13byMcDPivr2fSnG1ZetpRC2gY7NiNTwJA", 1500}, 
{"1Qj994hD27DRq2g3tL2feV3XXkffUXsMS", 1500}, 
{"19f7nPeS4pX5u1CSYnymzMpPZx5K9gumLh", 1500}, 
{"1Fkhvum7YANk14mQ4cRQFPXph7cHWLedXv", 1492}, 
{"14mYYUZJPUMgofvURnFY65YRSj1uqDzXBj", 1482}, 
{"3AkeFq4GYGbS7qv6ZqaUooFTtB2bhjVW6P", 1460}, 
{"14uByGebfPR3EDhA9sVvg4wXdBNbJYW753", 1441}, 
{"1D6iTqvbgcqenbkKNsFsi9zN21KH4KPPEa", 1435}, 
{"1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv", 1430}, 
{"1DmXZ4UWKQ2AjwLAvEK8R6vmZe5jYoFUE6", 1411}, 
{"15Fjw2BtLVnzWad7CKzxdSF2fkDctKsKpE", 1410}, 
{"1NScGjCDbwKKQhrUgQVhvkiWTiqDR2GaLY", 1400}, 
{"39VBgtWzS8eMv4k88WjLavUSUScjMXDRKF", 1400}, 
{"19EXaPSKix3guorGhApd1QixkwoDsk3Wv3", 1400}, 
{"139Gqqx4TESNaX1DAg5jRJCd3P22GGS1E1", 1399}, 
{"1JqdadgxgxrnbEnfvohxtaSNbHt52kVLtC", 1396}, 
{"3CXqwPMeRSZfAcXcw8h5xcv2QgxVP94cs8", 1394}, 
{"35tR8soky58TuUo1dKrT7RTsRc8SWCAZMk", 1392}, 
{"1Nc5Vpkk3qhFHzwrvHedr5uBB6ELSMuSmB", 1383}, 
{"1K4VSNMNqnmngpTXdny8a6xj9cfvyTtFfV", 1381}, 
{"14ResTzJYh5t9xDqtEsgCfXNjaWNSuA5uQ", 1364}, 
{"16QdwpazhZ2FnqiB5UauW7vRFqQjNBH7u3", 1360}, 
{"1GRg4w3SEp3D5HgJejyasQtD6UyTyrtAqL", 1350}, 
{"3KFumSNurzdgfsKzeLVC4CvsiepdBXwQEd", 1347}, 
{"1HW3Wa63msqwhrBYCAsddMGh1gWXABXWyV", 1337}, 
{"1GkqY6YQB6WKC9Hjh8oP8yojDufDYRCXkq", 1336}, 
{"194RLDTv6rjkDu9kX99mTBuK6KunAWRRkk", 1335}, 
{"1BgHppcDjzMYbfeJR23VHHbAFHUNunxAze", 1327}, 
{"1Dq9aaxg3DJ6rXfhKE5jKYQmcK3SBuYy74", 1326}, 
{"13kxWCuDWN1gGSe2vPmsSBVXyPfYLMh6M4", 1320}, 
{"15aKbxrQCJDEemv8LBeqE5mX6JikdporrZ", 1312}, 
{"1FUGUiJFcsLktTAkexy2ghT3Kus7yyEuUJ", 1303}, 
{"152kzDqjAVuPBMmJqcWvFbB7qkvigFXSLh", 1301}, 
{"19xjndVpGTqmFAC1ZL3gV6MpxJUMkvqSrd", 1300}, 
{"12bFfEEyw8MwT2oan8Tv99Cw15kYKL6aiJ", 1300}, 
{"1F6aQVRg1aWB5K63fNcaA79o9Xoik27GM", 1300}, 
{"372o41UryrDe4XuxgkagbByyVhH9niaGFu", 1300}, 
{"3Lhf1HGi3PjMQzgR5tU1J6MEwnZqWfA4QM", 1300}, 
{"1CqkuQJdi9txKMxw8hzfkYcefexz57nRAH", 1296}, 
{"1BmU4dAJAKEaDuj3Eswc66UxjbHWdVWu4F", 1294}, 
{"1KjjyBY36xDfaNZ7KqJxc1sQ9APESCXH21", 1261}, 
{"1Y6Lr71Htj7vwsG1mo5un9WBigrHcdAGH", 1244}, 
{"18iJBAX3BRVZT2i5vkh73TUM9UvAN1ASE3", 1236}, 
{"16P6cMXdmiiZR5d4L5aa793HwWZ5MomMKu", 1218}, 
{"15eSCVaJFFXbFitzNxWwUUCEwpS2dkZK2G", 1209}, 
{"1BBpy9Vh2gp78XMsdd8F2bYLtdtAfpsKji", 1207}, 
{"165JPvFVSTLqV8seGzY7mumNpzysVSoTKc", 1206}, 
{"3MTHTYTQeCZUeBD82ArdpJ65ctAhBBWi7C", 1205}, 
{"1APMXEM4SUeR9WBwvUVjAponH9vzeG2fjp", 1201}, 
{"1MVLP2kRPNqz8VJUy83LstUoMQzUjgq4Zg", 1201}, 
{"1B2KQvEL2wyWiBmxg5rNbHCU4zQmGDgiwH", 1200}, 
{"14aHSA3xnNpBYyqqZvLbTvrBYELbJhn7NL", 1200}, 
{"1EaChfhakuSdYdNekHZB8YHe6SdykVg8pu", 1194}, 
{"17kPKTWpDKgDES6RT11Xuz2qgyLNBsDrgu", 1191}, 
{"1FHJmaZ46UsX6gZzaQQqduA5xcCcsCLcYj", 1182}, 
{"1k7rio1YLfhN2JfaAsmsy3PT2oUdqiy8J", 1182}, 
{"1ABJkefLkbR7tRF2aLmFUNJAUha68CTEeu", 1182}, 
{"14E4jGeo7Gys3DvQThT9AiEq3yvmcpRZ27", 1170}, 
{"1Hn62xiJhDsFfgW3bBCPr83TWc18uCa9Du", 1159}, 
{"16xSAf5uYCrEgTfXxjrUgq9c5qSjZowSCa", 1150}, 
{"1GUT2NzCgVsjZj1DsBycCGXntoTTWjTiMG", 1142}, 
{"19NNyVDVqco5PRVZRqt9i7ECAP6CuyLZu4", 1141}, 
{"1DowZxD3BVK4EBqWoD6QaES8t277hgmWDv", 1137}, 
{"1Fyhd6BWJh6fAtC6rHu19K8FFx5a4aRaXH", 1120}, 
{"3MPaGxZfDKxu8srq5HSVtVjZ6SZcVgSBHM", 1111}, 
{"1N5ACP9k2wRUgC3siFRu45MoR9Xkvb6Wmc", 1111}, 
{"bc1q2dj7pneatd5gvqacxjkeu5g7yp6myav4p5pce9", 1105}, 
{"12yqUYtcCvDgiDgzJTT7DsSCoSifwYavhH", 1105}, 
{"1Dd3QKnvAZC17SvguLq8aoi8JLtQfr532P", 1100}, 
{"15USWMmGtSHnnkmcJBrwYrAjtjBg6i4N8w", 1100}, 
{"1AJuVk99ygzUoXZiAbBRnSaCMqB5QUJEsn", 1100}, 
{"1KmaiBSWEwmLcmq1TZzEJqwvmchS6t2n3E", 1093}, 
{"1MqgYXfsSAwraRSxBgiQnLCHugNVjJoJ2p", 1081}, 
{"1PiEKBgsBmCT4VuwFKLdGpXMNh99ebMPf", 1079}, 
{"1JeA5YGM7xX2LiP68zuzQpJ2T1Jf85VZRz", 1058}, 
{"1Nq8XVK1ocaBiL6ZswrDPmuqeZixXkFWEU", 1055}, 
{"3LvjVpxwsDikf4AbZmEJXWq6hNNoorSJFq", 1052}, 
{"1khUbG5x5irP5S8oaDDdNHZffymb5bpXu", 1049}, 
{"16ry3Me8ZJ1joi544mJocP2VqdAeWMQJ1r", 1042}, 
{"1D4PtqZ8gdX8cBR8VgLSnC53c1tGL9wopJ", 1036}, 
{"1KNxYaLy5HGZmKGH8NzJzUVhomHg84d2y2", 1033}, 
{"17mTkRHptC9sArDvENtqmVBKFns6h1b9y8", 1030}, 
{"1BB3hiRLobQQQjmoubthEp7gixHLxDy8pJ", 1029}, 
{"14g9K1s4SpV8k2CtwTNJt1JWoHSyXG4JWj", 1024}, 
{"1AyB2Ff33WjN8HyFHGa6UnEypDTnexiuVM", 1023}, 
{"1NxmQpXZD7yzXrTKdTBPGyVa9CphKb4i8t", 1020}, 
{"1khWP41zrADdWSNwzXQUZGpURPgXHTaux", 1010}, 
{"1FyGxvtPXCniSqivesC7DwMsKw49KrnU79", 1005}, 
{"1FSqgEhG4bEzTDLNxfeQ7hLz9E93TRhczn", 1005}, 
{"112P9ju5uTvvj5JZ6H3SNRy6mqxsXVnB9K", 1004}, 
{"1khbFxF6n3oDyMHGhBWjpQZE8TFoVYtSE", 1003}, 
{"37UTf3ruv5csr4CWGag2VCqgvenr2YzHV8", 1003}, 
{"14WeToVbjbByAUD8GGHRU9BJGwETBFLPKT", 1001}, 
{"38s6SbMfNpRTSZ6Lg4H4uookckzYQsAk4S", 1001}, 
{"14qdBdRTvT4i4QZ6iqRhrBj732x9EpoFQC", 1001}, 
{"1A6VXviu1guRweCkJiLQy3h9hzfoLawp5d", 1001}, 
{"3AVaHvreEHRuvtbmrfst9ypuZ4TPP5vpPj", 1001}, 
{"1Au1PEH71fsKfhgHSGN77CmH9tVmURriAY", 1000}, 
{"1NpC4gu2yA5NgdbL556EB5d1Qr2PiAe6rA", 1000}, 
{"1NjDkzqXL27SaJPuEYSE4XapbAJBgb7Wwz", 1000}, 
{"1nJ39zzTMJCygGxw3PZXKydSk7mNnC7SQ", 1000}, 
{"1Au17NJipcVz2CDbVJBYBajR4AkinbLT7P", 1000}, 
{"16g2TW2hbFoov3DThSRBdnETaS94bFvq5v", 1000}, 
{"18xjbYXKfohTNrX41g1GAzzjh1sjJPzRqd", 1000}, 
{"1PmLAqBiiCTpq6hc8BJ3wa8hJtyjNPdvHE", 1000}, 
{"1EqGWHKPrJZzLzUFTULLA3caYnQv53wQJP", 1000}, 
{"1AwpCykpTxiNhu6eTH62YcXVfBEcTM4Sai", 1000}, 
{"12zgpEbXRs9JzXRckvdkQFfu99jn521Dfi", 1000}, 
{"1Dg5eLjUu8tp5Rhkq1iG9XNPoryrPLQA15", 1000}, 
{"1Ab1BCNuYwGtfDKgJWh81zbeyB7HWNc9xJ", 1000}, 
{"1D4c6FjVrim1jppRWy1DNLjrx4uogZBwkJ", 1000}, 
{"1JecCTLDLgo7wEZrsYpUFLSZEpi6DJPK7d", 1000}, 
{"155AkfuHgY7mZFDm9d7xGgP1rqXHMtjukY", 1000}, 
{"1Mnc9YWgfSyyut8wdKDNznYhi2NvYnsqCw", 1000}, 
{"1Au1uZnK87eUMoJKRL9S3wroM29AiUQtL5", 1000}, 
{"1DFxKaDmq1cuzLjo949quvWqPA3UVu3hP7", 1000}, 
{"1LcKmgPFaXpJui5LMbaogk7A88kwdJK9Rg", 1000}, 
{"16hr6GDzWvBrkhSg5337jTrUnrs7Z9GdS9", 1000}, 
{"16TkpJm34XjeVdZZckTWAn1dqYbX5v7K4a", 1000}, 
{"13aNpzpiRe2VfupbroMWv68Q2VbJrnWdXP", 1000}, 
{"1H1ECjR96iAiTpiVaooQwcV9JHxf57vg2m", 1000}, 
{"14WWrJMGPo43mAoLXoH53pREAEUAFFW66T", 1000}, 
{"1Au1fALPbBY4qA1YRPUC9GBKm8gAZJ1CCN", 1000}, 
{"1uU9y4LSM3vKrD4R2iQqhMa1kW6d3kKUk", 1000}, 
{"1Dbvh6L8Ce22bnfe4uMVqXZb19ift8ohqx", 1000}, 
{"12dvRka7H1AydknnwqdsX9trXHbNZFzE57", 1000}, 
{"1L9oHjwBs5VVtrKFT6gXMAwqdobfhMZaWF", 1000}, 
{"1KVyYVs7qbzuZt4s6M1hKRwtQZm2QQZLiA", 1000}, 
{"14xWSU6vrV7H285PR96pGtvqg6XLfycSt4", 1000}, 
{"1KiQNazvLpchWb8rZx3VqhyaE56PXxcuYB", 1000}, 
{"1BNSd5s2wUm48PwVkf8CUYKabhM4iiHPmx", 1000}, 
{"1B8C6LkjpQHg6PnHzujfg3ujZ7Z3C9pEqW", 1000}, 
{"14SvnRSkHckB4NCFSNETgs7wbbwx2iN2HU", 1000}, 
{"1Mz9MJ3Tvm8vjZrdTDXSoJrL54uUGjh459", 1000}, 
{"1H5hXypTRciskxVC5nPGEF6Cw24F1AzC4", 1000}, 
{"19C5VdmSD3SF8f7Che4t2hxHHWPjKPGegt", 1000}, 
{"19GxhCCB59ZYYSTGSFrd5imG6wPWbhd4zr", 1000}, 
{"1PNwELxYci8bcMn3D9JBpqoANXuHTZ88YM", 1000}, 
{"1Atpo8TGJPkUtLreMrKzCGUUrxcYBHafA4", 1000}, 
{"1QFET85uxFHhud5T8RVYp8hzCbdfYHvz6x", 1000}, 
{"1CSXJ4kB7Y9hp3MVHSs7qbzsF3xuFcQLXK", 1000}, 
{"17pE1V6ZgNyPwsYtXaR1tJuZvvtcry8ukt", 1000}, 
{"1AbVjHyy52HpaHC9RCiSFszXzgPEhHcQqj", 1000}, 
{"1G6jwPp5dGbzmdvyX98REt4X7moBYME3qy", 1000}, 
{"1DMfS71RmW7961TowcM4WPQpMoTfZnjbgR", 1000}, 
{"17FPdPcc86QEfqoVuSBoc6khJDqS9qZUFw", 1000}, 
{"1BrpK5VRnWb5mVaNATXy5Cf8jjUHqF3pvy", 1000}, 
{"12iPz6KzKGX1UyodPsvKeigbsAkpGKKPNW", 1000}, 
{"1MJ7uvPRVc7GN3AUHvtQmUUE4S1m81EDxw", 1000}, 
{"1ECE8LSkmUDPYNAkysCJTzbQePunxdX2kj", 1000}, 
{"1AWe32boSBj88Uxvdu4nnVZffZ3oPeLits", 1000}, 
{"1JaVPjPHZgrBBwS3XW1w4KFUZFwvuAwtVV", 1000}, 
{"13N2qrZj54B8HrhKR65aneA3Cj2AE8XE7G", 1000}, 
{"1CVyPG2eMjQhFiS84r1eddFjhCfu4RfmDS", 1000}, 
{"13nrX5r86ohQKRLKaxQVvc7qJWVLfoFJ35", 1000}, 
{"1M1nMKdPHNehcnNa7z1DrrboKZ1FCKKAM1", 1000}, 
{"13XyAhrj45wSCJPwzutin3gjX1T2JLnh3t", 1000}, 
{"1FnSAxX7K93uzZDU7YBvic4YMdpoDBrzSJ", 1000}, 
{"1NzHXRDizgEGaJZfBG46k66QXpRzDrtpZo", 1000}, 
{"1NZGfyiibSHZDFpLHGr7LX1QqQfkYQ8gUw", 1000}, 
{"1DJv2uPEQi7UB7MSmeqmpUGuEvJnpS5mDA", 1000}, 
{"1NMLZVByBdAcY7UmhwCU4m1oUFVD9JbSpL", 1000}, 
{"16PAdwKR79mR24PqunHUkTjzw5hxTWMjQc", 1000}, 
{"1KxTeAd5sLdemKJUX9AFvRBivzYjVLfn1F", 1000}, 
{"1KsarsU3U2hVTQcbDWPS61HXt4oWC2AkgJ", 1000}, 
{"1HCwzgYBxrPtbRTupJTuoop2udJX6iW3U5", 1000}, 
{"17u63RjSg5cvfzYhWQUusJ4Pj3JQkC79Bf", 1000}, 
{"15LMDu1BdXe4hWuqv4XQtUoTczh1d16en6", 1000}, 
{"1C2GX9UtXGDBLTzdmdpywmgYxyPzWCmSTP", 1000}, 
{"1CoPFgnF4kcXizu2efzD94ApdUPc73yZiC", 1000}, 
{"18ty9e6JoAoTFE2PotYADAGaBDX1n87tMd", 1000}, 
{"1JqbjpSommDxXJmXYPBXidcAw6ZPmd7v3n", 1000}, 
{"1HYfivTqoSzjqy6eawyitWoK8HvigtU3yb", 1000}, 
{"1ANSato2K79wt7Lt1SzaShi6S2Zwu1fc4f", 1000}, 
{"1PVtFeBMdzPyScdukxG6Kom5JiTzozU72H", 1000}, 
{"1EcJrSJTGmrhHYqxFwGjcWESEDTMwTyTEj", 1000}, 
{"1DWQ6tDZaFiBxAV5Gm3JQCZAJQQ9kU9VfX", 1000}, 
{"1KHqggfE62Gkhwpt2AyH2XhJrpLA9SXDoe", 1000}, 
{"1khKqY1WeuaFqzq4spQnN2fYMNNuMtmxj", 1000}, 
{"1PyfQYtsPnGd6ohu1HVHnT2HigCicF7Acp", 1000}, 
{"1MPStDkvNuoQo3BkVqL2dtyu62hNk8Bgn8", 1000}, 
{"12qHoC3iB7mRaMF1zZcoTPS3mqKbUe4qnk", 1000}, 
{"1JbnJYGxYjRSTkf17gWuxmbXvA52VX1EBP", 1000}, 
{"1JE2qgYcf6bX8i4eGAL39v6syhcsWR8EKE", 1000}, 
{"16D68ce8dDRqospW425DAD4LizRXv7rC7u", 1000}, 
{"1KSKKTX1Vh4QCZYaxU7Dj9MMKUqwUA6qJT", 1000}, 
{"1J2a36ac4LoK7bisFci4NWeKZ426BZKqJN", 1000}, 
{"17tEH87i9gpoFYbs88z2PoabpNYChMfs1P", 1000}, 
{"15cq9ht4HkJSmgwDKneftyxwuYGvnBrKJi", 1000}, 
{"16GJ3zu1p6Ps59wRLGWPTUXFnbyBXdwkCv", 1000}, 
{"1MD9WPJwzHVPTvXbuzEaFHaqLqqzvypxUN", 1000}, 
{"113Z8q6zh4vG1zp4Z845mPviuTLcyThAbp", 1000}, 
{"19FXykcZNxz2ZbuVW9erRNosduXDXTmHy7", 1000}, 
{"14Eo7CebKpMeiobNVdnahbpEWtbriiYoTA", 1000}, 
{"1GDV4cz38Unob83UpaETmjzqkyfoiJmYjG", 1000}, 
{"14FyNCw65L3ugW3LaWKv4FUK64ZWyzPNNM", 1000}, 
{"1GYh7MW31zFTirbQGaEV6CZ8hAAhciwHJB", 1000}, 
{"3Jm1xenEzSXufMrmyuKdap43hz4skYEC6u", 1000}, 
{"1MQavFm6JSffUcAk13uAjku6XgkuqNjvZe", 1000}, 
{"16EwumVQQcGjqgcxkJ2J75sdhmjLH9eaC8", 1000}, 
{"1FcKR5SsN1pQxkbHnTCrSPb6EV1eWq8Ydj", 1000}, 
{"1GXhEFqai4hDwHHJa3wU6y6mB1Yfvxwt5a", 1000}, 
{"1ABrBxtxCUjrw2MiV3AkYcUfq4fnhALASw", 1000}, 
{"3PyRWFMLSPDunU6TsMkKs39ikwDpk8LxzG", 1000}, 
{"1EjUUu8u3uAyfeFTKm2hSiES5MXAD3KU8Z", 1000}, 
{"1NZwmpjxR1UgSwB6MccxSs4drJMPSC8BaZ", 1000}, 
{"1DddMaMDcbRH7iqVQeeodofrg4bSy8ahUD", 1000}, 
{"1MNXnP1MnTobCb74EbzB9ktaAzVFCET7XA", 1000}, 
{"1YkCSviQrxqpmfwRp5seKyHBGrwykgNaG", 1000}, 
{"19yPfFkt5JjbddDdsHxBStT4Rk5JJQKoez", 1000}, 
{"18U96dbACunfUheXyDWTMpqa2CFBE8CUfv", 1000}, 
{"1AjAmmPSW7KTPLdVaa7ST7oywypctoZo2F", 1000}, 
{"1Jsv7D3yoedaDRd4Pr84C5DU87sgcokqsn", 1000}, 
{"1DTWt5uvgPR78xrD3LEwL3dKQmNQwekmT2", 1000}, 
{"1D73bDndyazRE4PrHfsgQaR8AwLd1v31jA", 1000}, 
{"16NZmkXCToQ99zvTwibaFK9PWYF8RhTZf8", 1000}, 
{"1ER7oxsQRtjsdZSKi3pY3eni9GvVvBbPjA", 1000}, 
{"1EqSDLv7Kv38JEWWU13Dn7TbiJyEMKKdKV", 1000}, 
{"19uqAzejS1ZXkmHGNJEau88ooob4QXjmEt", 1000}, 
{"1HzodEgsb2TsvWAwY9pWBwJAVawXReD9KV", 1000}, 
{"1BDokNFscNnkpRUegJXKPGeqVm8y7L2Agf", 1000}, 
{"13vze7Q5jv3LRzDk6Q1gPSu3nweESEZdf6", 1000}, 
{"1BZyajZKBLpgxcL8rS69DT6SAU5pqLddYq", 1000}, 
{"19SuKg8Nfp98Xk2MYWcMHtd5o9f3FcXZkr", 1000}, 
{"1LtPgZNadP6efq2K54Lui9S4SA2gMsZEPc", 1000}, 
{"16ULF9orVaZS44baJTXN1ev16FnRUSpJGS", 1000}, 
{"1Jbc9s4fpi5x84BoUe9SBLtmxWFAD5ZjKq", 1000}, 
{"168w95Wf8tphgM7DPREXr8zLnVoE2wJCAN", 1000}, 
{"1KfmQppd29BQjmPimfb73fRGDESzFybVn2", 1000}, 
{"1F2bKNevAVDJbXy6kYPghqB7BTLtRzfkYb", 1000}, 
{"1Pnvt4ttbvexku9EvQb7vRyBP5qRpRrGX6", 1000}, 
{"15JZnwq2NqSNtMPbBhdQddbyimay4xvGyA", 1000}, 
{"161kViPB1QTxid9rHXCbQDFvS72Mgfc4y7", 1000}, 
{"175Vm3p3LWtJJdN5mSpv7RQWhx8tqUZzB5", 1000}, 
{"14GHoKsHEfR618VFoz9ahLwzxcGkNEka3q", 1000}, 
{"1QL6KoM1uWtTEwQ7vJXY7J3Bpg5mMEzEag", 1000}, 
{"1EYREFWkPX3CyA5uk5CZByK1LRpRCgXorF", 1000}, 
{"15YEfnK5PpBWkBuNPYYFTeXLXRtyqsC9DH", 1000}, 
{"1Ek4uWz9RbGWKZdGRedEWT1a6SKCFYrvsw", 1000}, 
{"1Wog45X48gF5wm6Dtfem8WAQGH3X74p88", 1000}, 
{"1LTxwgxWgt6qTb6843pMGpAAVZt1uhosq4", 1000}, 
{"17diY4cG7W1o16Q2Jy1MFJ7PVPLjJQ38Gi", 1000}, 
{"1S2PWYeAEhNnpjizaAmrssfLi8Zfroxg4", 1000}, 
{"1513Qr2KAM88LY2FSCq5JCJyd4LorUYtgM", 1000}, 
{"1FxDvUoEJU19Bq1ywQX7beQcqkn7cUp6jX", 1000}, 
{"13Foa8niJE2nHugJ28HYBUfx9Ww4QfS1pU", 1000}, 
{"1BEoqMoicfoJ3n92dpupzCdLEUU46kkz7M", 1000}, 
{"1Kmvz1w8wcNGtMUHrJtKvJ8WsK4NSszCiz", 1000}, 
{"1NfFjW1muw6edJ5npxDxTWKb2tekHVRyRi", 1000}, 
{"1GzCBKcQRtRvrwaJDQPuWAub7fRpCofL26", 1000}, 
{"1Dw7894vBxRBbHEzX2SLkXBHK9432ckre8", 1000}, 
{"1Dp1RTReq6Fr2ABALcbDj6mtxevaLCz7R", 1000}, 
{"1Eb6HokTzBSw4BSFVuMhi8HLFXJ49nykZE", 1000}, 
{"159cyC5eTgy2SqNGnKipJdg53TDMae33eF", 1000}, 
{"1EAaETBVzBAYMdokQy6oDV3ndtsEgyNuZG", 1000}, 
{"16pMWunTk5ayjPk91cc5ghp2DtygSmVosb", 1000}, 
{"16EjMe6ufEzpGgDryRJni4XXe8fzaZHiVV", 1000}, 
{"17GURBUGs1WZN3DtqCDLeBFvznbBgQbAPm", 1000}, 
{"17Mbft2v8x2MXyFaQQAJFUFsEaNS2hx8Nj", 1000}, 
{"1DkP5oAi3PbyvLndmqsUyBPJ1zpqHfcHro", 1000}, 
{"1NjqzRPtJ7ZFJHnF3VfM1rHkCCgYCbPNBo", 1000}, 
{"1N3iUA8sQXyv8pZekHEmmVx4JDZ98MPPBa", 1000}, 
{"1JBzBYhWwUDwukMF98E6odcEG2Cq2myK8W", 1000}, 
{"1Jq4f2fCjBJBwiCmcmtz7CW8RTuamcfoQT", 1000}, 
{"12mGByfmJH16c5hQApi4N2eHJKfKrrf1fm", 1000}, 
{"1AyvHCZgfFcRLUCzs3W5vkyX195FCmsimK", 1000}, 
{"1JqT4EpwmHogj6gayzoM8sZ18nfLA8Fb75", 1000}, 
{"1QAbhtkLCaNFFfGagPiqCMZecupKjZBBbh", 1000}, 
{"17gBJdE7xd8Xs7UwotuAb8EbGbPy9TvfHK", 1000}, 
{"1LC1r8TX2SzZtzWAw6DTKXv32RWrvKbCLv", 1000}, 
{"131gJ5QEpk74NdQKZC4FHW9q9N4htvdvUM", 1000}, 
{"1FcM3U5XKLrYSx2CY4f3H9W8AZsKzFTVSA", 1000}, 
{"1BBXEhXcHAA8jvDUvtakz7Hz4zf41Q8zNg", 1000}, 
{"1JH2Yt4LWPkXjCw11GQpAf6SahjknVn9iL", 1000}, 
{"1DktWqGjJQFmrKELt1nQrdJWmNMWBxGQV9", 1000}, 
{"16fKLByWc6dWY9tPPvY1SsajYsgDfsmwf9", 1000}, 
{"1HS8i7yiFxiwkFyRGdp6wTYKajpf58BYdN", 1000}, 
{"1QHDQi1PVaNNn7oZZAWAZCiqRmQWouv1ey", 1000}, 
{"1JMHwAaStUj9wq8QnJ2KuRRx3pkuoPSAdr", 1000}, 
{"18iMRHgQ6FAFgJU6pU8LyQ7p31BuNPEL98", 1000}, 
{"1Pv5dqp7kGyCXhfmjKjpXmfWZSF8ARoFbu", 1000}, 
{"1HKGyCvg9xeLtv63ncC5FokeGzkySYzcHK", 1000}, 
{"16nFQiPUFeUoyBpm5uZjA5A7oytjxdPPFY", 1000}, 
{"14K8D813nMR64UMbJwf7fewNdT8SCFhgep", 1000}, 
{"19b6eK6ZPQPtGpniBzt3hoXxdJ9Ym2oZ5d", 1000}, 
{"16wNv4jDWLa7CcM83GT1BvUNQKuU791bmD", 1000}, 
{"1KQH9acNRbtPbSRSd86WM5bJkBVjcVSyNE", 1000}, 
{"18G9aLZErQJhcKHD12ufmkLWrvGFHx4BqN", 1000}, 
{"1EREJQuF2H2GDEK2yJcRBZsKYpSg42fN1W", 1000}, 
{"1EjELb9yAKQK7wdsxtQyPhKxHe29fjC6bP", 1000}, 
{"15kKNi3X1iqf7KvjRto6U8ThuybCteJWfr", 1000}, 
{"12KZaPyqRKFwLk7oZ7opKoG34D7dDVepei", 1000}, 
{"15bSWi83qj3U6oVRVWnP2wsi952PxzPMAB", 1000}, 
{"18fvb38fBeSgyY31hcKcbYZGQ8TkZr5F1c", 1000}, 
{"165vm3yMjE5ndARKnx6Mpev2V6YrkDXWpk", 1000}, 
{"19AQEKDM7UjLmM7a3YDf3mMyECbvwv4V5Q", 1000}, 
{"18ukHgnFwrro74Knn6KqQZRXVRNtgj7Yrk", 1000}, 
{"17TWkx6PHZL3EML1Pc7wnp7nNERqisaU4E", 1000}, 
{"1DG9ikTfNQJ7AcTWKMCAYyY8q2h66qht1Y", 1000}, 
{"1Coap2Thy9VKQT7AuGJauLJcepJLXso9F6", 1000}, 
{"bc1q2jqt3dnyghlea44jyp0tup8lav7mw8nhw0xltu", 1000}, 
{"1CHnxKrYjYc9pVX4Z8uMWKM3Gm5NCnh78e", 1000}, 
{"175zrR3z4PB3ug4YFBrk83tiCgbtfFGusm", 1000}, 
{"1y75TUkBQjVmg7C2GRA6rNX5V7b5Xhd7s", 1000}, 
{"1AeLVWnGSFRVrqsDQAtza9ETP8CQtMqQYy", 1000}, 
{"1NDW9P5gb1tBxuAk2vjQqk25V7aUcmitPL", 1000}, 
{"16m7L6UUTxDDtnYdcQDZaePtFLdz3maw3y", 1000}, 
{"1PCuHryZkaL4rqMuo6EGDs9YgpANVaSkvu", 1000}, 
{"12PxBAuwqJZ52KhxuTtxyURQBAbo3kVKV7", 1000}, 
{"1DNMGfqyd3Uab3QKBj7RNy8FafRNi9ymxG", 1000}, 
{"1DaGqhQJnVnCKcJ1zNMG4V7tpjtgG4QzGs", 1000}, 
{"332Bz16NazGs3JrvRXSP69sJZWvKrzp8Xv", 1000}, 
{"1BDJFR38mHkC8TxoHFyz6Mah5M3sNBXheu", 1000}, 
{"1J5XrcQVMvwe8JJDVdfxkhtEfx2ABThuH9", 1000}, 
{"14fJX3SnfzR5CmkNHtgryYMH1T8p3XGFu8", 1000}, 
{"16RYY5Z5gM423MRQZZ8QTcxmfNTmtoWho3", 1000}, 
{"1L91DAFy9Fp6ixv6XZALkwQQFb6KR271Fr", 1000}, 
{"1ECQyPuL94zKHGguaweHi5d21zy7xHchsn", 1000}, 
{"1G6qkSuiwuXSsPT3VdEWyeWrvVwnjnUnCC", 1000}, 
{"1CJE97kZDvtdASmmDaEJevAm3NHRjjCe2a", 1000}, 
{"17gwo8AveuUKKeoM8RXnjnvb2VGVrd1QQg", 1000}, 
{"146qNDmYArQHhRoHbzie3BJoFKodFvQ7jA", 1000}, 
{"1BcaHfYuFzJ5BwTjDs8ouakVY9omJPcjFx", 1000}, 
{"1PAgNcgjiTok3Nr4NGQAu8DoPceSHxEqra", 1000}, 
{"15e9RUqW5vMRAPgkkJr9NrG9Pm1qbQPdqD", 1000}, 
{"1CvcUmJqLi5GCBVyzvdEtttUprcP9Fp5Qj", 1000}, 
{"19V3kjt3NsmNTZuc1XVAkd4fi1jgAU6VXy", 1000}, 
{"1NdG8WCsZVf8GxiQCgdiqJtK7WtJ32gmeY", 1000}, 
{"1Hda9wPWM1yUgNqCBjobgXukZ5qbSbLurp", 1000}, 
{"1KnAtWqccah5JjbNxjepYjJwum3PZpgLpX", 1000}, 
{"17iZTzzafJGys3gNQyhyJRgCzreRCz1Txr", 1000}, 
{"1LxbYv6a2EEJoo3yzQ6vf5sfWnDoCxi5UD", 1000}, 
{"3Es3kqHt55jCf3xAfTJ9tvzJkhCTA3uxyS", 1000}, 
{"bc1qu89mdnlqdz0jshgyhmzz7k7s8gu9pa0zh6jvqy", 1000}, 
{"bc1qwzt27scr3umqh8ta8tyrrs396z0cl2mk4rtxq9", 1000}, 
{"bc1qm0vdx2n99jlv7v434p4t6hq34nru4xctpx632z", 1000}, 
{"bc1qljhhlde5xef8twdysy9h5wsc07zwhhegc9sjyr", 1000}, 
{"bc1q3luqsswtyy6jsgapauk7e3lsjy4y5tc68wy2vs", 999}, 
{"bc1q4l27853dey50jcm0ewvmkrkvue9km2vvc2j9pl", 999}, 
{"bc1qamrj6ds3hyn484dqu0eh0j99hhycyczrt5jag2", 999}, 
{"bc1q746lsvfgp78fxdpeyxmmqr0xyw0g352aaxcyvz", 999}, 
{"bc1qd0u2zjq3cvjgk95x830e8n4dr6vwlnve468gv9", 999}, 
{"1JmJqtB9LP9JKNvaBW1rzp1Z1R684e1Kks", 999}, 
{"1khj2b7MAD7y5bMvt2PZdSh3EzK43Bh4h", 999}, 
{"129DaqQS3i5fpRR4D128DsNh9kFavp4RRX", 999}, 
{"36Sd7HLC3kEuMPcMjffE4aGJnVx5KpWbjk", 999}, 
{"1khqnEzuk7XB7he4eWfAJ2e5hm6dGdxQD", 996}, 
{"1C76ALSqbG8FbXWB2P24hmrSJ11h6kRYdG", 989}, 
{"17vMvB48Z72rUt9EBpuHJkEfvBtMB2QFKq", 988}, 
{"3H68vzGYWMComuXfo3nczyvK5jTX6DYDLH", 988}, 
{"3LgVNVuT9zKszKfHxDpbzMAETLb2tY1v7k", 983}, 
{"3D6JUDpf9YqYYPhVqAJYQUZXJywMSXUNLL", 980}, 
{"1PpLbwQJdKA5ugvJRGLBNYFiGttCmFkWjj", 978}, 
{"1EYFJBtNfhgKcvcL5a9ehxCcgBpTaEFMJE", 978}, 
{"3CTgE3HLQGQ4yMwJcqtkdegNP6etGMz4zn", 978}, 
{"12JsKnPzzq6e8CctzGpyVpcQZ3CTnkdQ7X", 978}, 
{"1khNhkaKTWUpMJoASuWiAMyEApJjHajoZ", 975}, 
{"1PP59WqzNshVX1DmeXRAFswYTaqcTcUeYe", 975}, 
{"1Paos19FGTgK2YAvrwZAFL1NgymYPSdPr9", 975}, 
{"16xPL5rDYzhCATF1Rp4pywYSSKja6kpYRJ", 971}, 
{"1Lo6kVk3DzCzkakDPGD2tuGUbp2gCWuh77", 970}, 
{"12gM8hAGmMpjfkTBHbiB6DaerH45vvMpBU", 970}, 
{"195ECQtjYCx5xeSFTWKAwR9DAyxESXpsvW", 970}, 
{"1LDQCnsNCsy9MBEk6xCv8JjHdRuLAQL1Fg", 970}, 
{"39tznK97W29tQWo4QewcSjhRf7XeyFN1WY", 968}, 
{"1HCefrwvu8Ptkr5kpQ6qJyvRgV2wdB1rEt", 967}, 
{"122vzE4D9VC2yYTmhrDq5ysPHHx7nd3gkh", 966}, 
{"1khvHY2vNmLbZAwySCvJLs4GzJQfdHmjc", 961}, 
{"1Fu9pvuV6XULRaohYm7ceVvy2rGjizPnVK", 960}, 
{"3Nje6kT1r4oCGn2DLDNrPajc4hyfutsR2r", 960}, 
{"1KHyYQk2zKCvSTbM3gPtbEqb9zwxFtDDGt", 956}, 
{"3N3QjZ8NEdF2btqe9TzsoaPDeTi39322hk", 955}, 
{"1CWR2UC9MYejLYJaoUFr6vtrhn2MLxCFy", 955}, 
{"1PnXcVeQjrn2z5vRuPi2F9ipWo18deZGJ7", 952}, 
{"36H1JJJHQkzJmJ8sJcqcHTNSUEDbHYWj3P", 950}, 
{"1Cv69bm4ax8ZBBh6YrcR4NQCPpJbkPLoz5", 950}, 
{"17aEcvgXy9o8WChy2NQ25PykaQmPaSsKuh", 950}, 
{"1B1mktueQwNbtmxPgiKqnnUgQonPud3HLZ", 949}, 
{"115cU7d8YVkwJb6ffHGeT1m3rzdt4itCid", 948}, 
{"34yZVbAN8odvSoq5vWeZG6cSWJd7ExAG52", 948}, 
{"1Ngvep3PBxUQvBoe8A5D4eaAkEi7NQ5a9F", 945}, 
{"14e5om1rU4PujGsMesbqgyP2s3wd1CDsCS", 935}, 
{"35Zs5828MTqe93e29rg7groiw2fA8T8VJ3", 930}, 
{"15HLPAr1sxS1ooiUGUj1d93naMgXDANR16", 928}, 
{"35jgYt9gREGqCaCQVesn4dbdCsVgD6PJh8", 925}, 
{"1NhoV7x1tsy79kNcpXadoA51ZCjRReDDMF", 923}, 
{"1A2hqHVSUERAT3t1yJ7ggYCQccvH6pZGZm", 909}, 
{"1JXKXFuB4HZf18JnpKADe2R3J8taoCcQEE", 907}, 
{"15bfTWfmB4hTtvtcVSaMWWb5d2bAPEpKyu", 906}, 
{"1EGZ3HcxsG1Vf7YV355CGfN8eqZ5o6wqkY", 905}, 
{"1CiW9KV14mCUf3FkxztGGvwp3z7dQYEaKx", 905}, 
{"1CBUuXp7WkdCB4oXdRWeBUAL9svQANycvt", 901}, 
{"1NS17iag9jJgTHD1VXjvLCEnZuQ3rJED9L", 901}, 
{"38GePFkuCgxExTC4yy7Tx8RiTNb4hcs1UG", 900}, 
{"35HkAAAArWjULnsCo1xQgQjwEgsQHeyvQ4", 900}, 
{"1GRvHRNP4cJb61MqjK8UB1pDdPnnQZzn71", 900}, 
{"1PdSv4K7zbjTArEQZYzRs4Gq3UnSzEZMjS", 900}, 
{"1MBXyfspMoUgp5AKRXUe7Esz6FCbedrzJ8", 900}, 
{"1W29A8De8AbPgnZtxjHZy3HudukEYZos8", 900}, 
{"1Hbg1bL6pwECNYDcnwNDp2mcx2c5V2HZA3", 900}, 
{"1Fk6fXbSWCtY8bSfuwvqbGK8Yr9tFsMEJw", 900}, 
{"19HqW4tfDohCBUtYSxyQBgm8fBZm8Rvpmi", 900}, 
{"12m1FaVoorwGhhgFBPsDagc7xaLsT8e6pS", 899}, 
{"1EpcsTPJyWqvdvCePz3JvUpDR6r4g6MPBE", 899}, 
{"1DS5WKcZV9QujusSTNX5igiSzJnnyKRLeB", 897}, 
{"137zjnSXZs7Wdhg8zCoAJHz3NPgX8WtPPv", 896}, 
{"1K2aDBwgGLrx3n7vBuSbLyp42ZzVzM3aBz", 894}, 
{"1NnVhmQsiQ2XKpcaRfHned36xyQvCX5oUQ", 894}, 
{"1MyFSRSa7wv6kC4GKSE6HFZX1fa8kBH4N2", 892}, 
{"3EKjBtzaCgoG5t4Sjhhk5ooonbSuoMkXw4", 892}, 
{"15rFxiH7n2b6iBSiKDo5DX6tr5atUNhqTM", 892}, 
{"1N3P71tefgcc8aLiid2rjhB41SSD9nKvBa", 889}, 
{"1KWrEh1ZusVvNPvYwD4meGewLLdNn2jegH", 881}, 
{"1F5RtdjZaDSBHmR3nRaveHTMgLsShC1zRi", 881}, 
{"1KURKmDz38wdXdGKthAyD4RFxBmPFz1FZu", 880}, 
{"1BUmk83wcYbinUs7Q3GQWDFK9jYgpZQoVD", 880}, 
{"3JN54cFYmecMxkGsff2gdz4YvFjBZcgFrz", 880}, 
{"1HaG7Y4B6n8wsp58njSwvjF2oWoLcyMF1b", 879}, 
{"36ghLdCFBSZK3hefMLnWMdWjL3X4K6uJ6T", 875}, 
{"15ATyN61qpsBjEaR5CEEwAUpmdavQnv8Yn", 875}, 
{"16mEzobs4wQPuAMq1C8QSQafcDHvzczVcs", 875}, 
{"1PpDzas4HuLpTWdbAXYbvkLXcyEdY5ensv", 875}, 
{"3Fqk9NxLdr1UNurtwH4iTk6PoExqxu2UKk", 872}, 
{"176ZedfT8knbKLWqFMjp2HrKcaaYQm8Zj1", 872}, 
{"3714ASP3oGt6PyYEye9NowXi2yPW9ushta", 865}, 
{"1Jp3ncZNfqGUohzNPpQ3SoMSLreKVRVSqD", 862}, 
{"15mkHA8s76bk3Z8ohxF4FSwui1Xs8dGxvH", 862}, 
{"3Md16NeexqLTj8o7Q1fVEgwbn13Lnc9Z9o", 860}, 
{"3GvqaJFxmSDEbshRsrdEQTKRTjoL6CmKUv", 858}, 
{"15fL9TZxr96o769upAmHmEowaBfUBg1rm6", 856}, 
{"bc1q0eg0u2ck3waztcwlvzclyn0l0mlyha5dzhk3vc", 853}, 
{"18eaXno4pmPzSBzmMqteXd2wU9Wpwiqdd", 853}, 
{"3FojjfFaC8n5FH8w7a9sZhpyNFV6ZipGpo", 853}, 
{"1EgWYXrR2isggrBkNyUw2gYv9LUqxReBmG", 851}, 
{"1KWnKgKzJniQp1qkL1E1tgwyJvUUTNBXVN", 850}, 
{"1PiEenKA857w252gq6S8GJt22jUytW1uac", 850}, 
{"1JEMGVcpyuFBc8a9qtvkd1CjoSHKsTxs1e", 850}, 
{"3PoRGiq1C89JRY4i4oUXEBC8LgZkjvCz9b", 849}, 
{"1P5goqbhXjnbV4iNuYubTZysZL8Urtyi4W", 845}, 
{"3LtgC9b9jtfRQdvSGmsgdrQmTddXddQkBp", 843}, 
{"33EuBCruxHo4X1EbnZFzqBLTf7MHNXMzXD", 842}, 
{"1HyjXZQUznXJ2QcHoQ2e4t3g2etYJ541jt", 840}, 
{"1Bf78poRZx3w1gic9f78huCev1YDMaDMNa", 839}, 
{"1CbjQChgb3dWCsPAtMUoRbk3XQJHJAQkJz", 839}, 
{"1QC53NSmxzYTA2MSEMERoN6KLMfbte9xFH", 838}, 
{"1JtmkEdRU6QmhVdGUzkNrRpSABzTNJsKJa", 838}, 
{"1AbtwYk97uGGtRg3ZH42Ldiw9g89VBBDZ8", 835}, 
{"3LH7nbuzsa7xPfz5AHhinMvBKTvqbvspcv", 833}, 
{"1BB7zbmpBr3HogcH9Jkegz2umWHNvQLiBz", 831}, 
{"37yAZupzBJBqzHgC2qi9QR3f8rmnhJwUDw", 826}, 
{"1FmLMbBLwJrnm3giK69WtKrH9yQZqecDjD", 820}, 
{"15jwjFmZZJkmFUEBnXPvWNWvLT38dh9UyW", 820}, 
{"1AfdbCzDrRrMEqAXkF8kxVRCkPzB8HxoHD", 820}, 
{"14GgLGbPLi4CDVS9YgjvVGxakTfhmpEYEK", 816}, 
{"1PACRBuSqpztWeJVg7Sf1vXUQgLEa2LY55", 816}, 
{"1JzFJ5ceSZ36rkCZjXxy7r1M1eEqC3vjxQ", 816}, 
{"18t6ZNhg2wBGDECuvZhmexp85xEeUgrf7z", 814}, 
{"1DEbGccBE5SpcGvjFaCUqvv5TLDuUqGwvU", 813}, 
{"13k83ifQTnUdW99hecp3YMD8qNuXFBA7EW", 812}, 
{"179DxuJjTjEiDuqDvwA6ex8wxeN23vBi4J", 810}, 
{"1EaGC2c51R2523aCnuGSu2HD52bWuNMypV", 810}, 
{"3GYvbBGdEXnzpdy2yiBotw6Zc84ySMCSw8", 806}, 
{"1AMkwVLnF3xnap4nyFAYhY8FdF6jdrP3jD", 805}, 
{"3FeBBT5deWxkBsFrAPNnAcJVt7en14Kz45", 804}, 
{"13wpTmDVKY7cNqsdYJqcTTZa9frFFtvpGY", 804}, 
{"1LnbFGdfKCxpktKJCMRPhtdAZbb88T1nY2", 804}, 
{"3KdUgzWvqBUMjxjXETFCAuYjMh79bWQmBF", 804}, 
{"1FZAt7NvBfVSxK1CSZYPENSdqoAB2y9gC5", 801}, 
{"1KFcaAvK7N9byND6ta6njr2udiM7Mnp59", 801}, 
{"33mbGqVKyGCongyzDA4nkpH9xrc2S6TJaT", 800}, 
{"1BZrv9HJKoWCFjZzqT2ypF6fx43FgaujxN", 800}, 
{"1BsHJ6ZkCAJmgWPwuTiT96Aagj5EX7JuGc", 800}, 
{"15jELtRC9v24UNAKYaoiwM8S3AhezVib99", 800}, 
{"1P2ZAuW9nUrFfwgVjfL2SA9sPXSruCfzp8", 800}, 
{"16ugeFMXnN7WA4SYnmLRxDAniDn4mjsu8K", 800}, 
{"1CXr4X3itmt51PxmCB4X6kfQTsdohwMBAr", 800}, 
{"14bzNMK9AXFCF3E6g6wHtT3dMECbpxwwam", 800}, 
{"12ub7BvRSke9oqGLVUbLVnELypUQRrzGRU", 800}, 
{"1FmM2ou9XdsULzyEbFDVtFPNDmq6UYZ5aD", 800}, 
{"19rr5k2zdsuBDhGKNsHjr7PgcZVT24t2DG", 800}, 
{"18ryUMvNpTSfNy147eDJPhVzENoDpFnkCy", 800}, 
{"1LTR94Yxr3ncBDzfYSi6nFPEkScmd3Eazh", 800}, 
{"1J2MBfr4Ss69F5cyvPRL5Qg8Ff8pRzWaoY", 800}, 
{"16Vgotztzr29bux83NEKvZY5LpgAkFqHfL", 800}, 
{"18MtuPmrLozjTaDCHdX8FCc3du3R4oR8gp", 800}, 
{"17PdhWQrcAy4hFf5mVprSRMyBCUDwaZ9Cr", 800}, 
{"15XWErJFYjygF7Agk5AMfn4GKN9qCHkx8z", 800}, 
{"17TaVu5cWyM7SfL5U6vyjnsvn3aT4X6mhd", 800}, 
{"1Fos7dAzC3WfZvyHgPnD36Rd7CvcPxZctc", 800}, 
{"1Bf1Tus6gmULyskz3ibCpRNGHPE8P28P1i", 800}, 
{"1PwfZ5YF6Zu3RMKjhRHPxePipeKHki1p1Y", 800}, 
{"12m9nY8eVLscZYeKoiXrxo4Fydx3hky27J", 800}, 
{"1DkSPEx558McnXntvbGMM98G53Cf2zhvkD", 800}, 
{"3NWhMf7raK5voWqHyamyEwKMuZbuYGEX26", 800}, 
{"1PSG9wJZ1kSpLXkGzGvhjfpSTasQbCT3mU", 800}, 
{"1L6Y7BWTJz4baG8EVD2VFSgcrWbM7Wuf9H", 800}, 
{"1JQn5WE9Fsu4WnGsjzsRgEF16v1mdTEUn5", 800}, 
{"33qQe9JKkeqKxjTJNqzBfc5EHfWYNvhRmM", 795}, 
{"3CzzpVbvf7PAxtHcvTGybUBXFCqRoNG5dm", 795}, 
{"1EGVEt7gqCFDQwtCWdVdzq7NKr1g5BjQ3M", 794}, 
{"1Aiy7vAUyEsZa7tvwoFNZdNUtJrP3LBoZC", 794}, 
{"1Q9UWogYPPG6J8V6EufxRxYiuxx4dSEfF", 794}, 
{"1G9BjAFRnSdCaVzdVMXYMd43CzTZ4mx6Qj", 793}, 
{"1JtyL7Ka1ur7YAx5RvoHL8hh857wmi3u6J", 793}, 
{"1HopU6SxVB8RpqPgsrV41CcmuQ3g51dw8d", 792}, 
{"3PKASkiHEvM3ptFhUdL78Jky6oEZ8PKDBV", 789}, 
{"1Fmp8fvEmTxBYJF7YTr6igsTV3DBWSERKj", 786}, 
{"1JZwtPg72uUp26izpCE11gywmTWv1pkTdv", 784}, 
{"1CBjRAP2oUPUnij7EgrScqgzmQkXMP1tWZ", 782}, 
{"1HgZ9fMye9nwna5m4fL53aTXNsQ4fvQWAA", 782}, 
{"1H9TvHe9YjeLdKQMzC3Di6aqyr9gunMuh3", 782}, 
{"1GV6inf4bC2kQjzjGdVGy6kDorsZuntUip", 782}, 
{"1ECoeDfK79CNm1Mzx6NMMkZrHVocwNg6Sp", 782}, 
{"15SiYmTGYC4VDbN3aSqmD51NudmrjH9TV8", 782}, 
{"14RPrdBWkrhvnHj3E5bqafka74KeB26c5Z", 781}, 
{"1Q3GV4F5m6ArzCs4KPJaiFtEEYfuskk6cb", 781}, 
{"1QHGH3uXNSt4hiQMvjrgn4vDaMDTsbZCJe", 781}, 
{"12Gs6b6aM84ALVREn653gqmzAXoerGHg7B", 776}, 
{"1CCXLxWHKc8x4QV1C51KPUefHSZshSBX25", 774}, 
{"3H8GUoDhpcmx3xyQznooMhN21z2vEXkjEt", 773}, 
{"1MxTowyoeDskh8XMyAMco8Qr3w8PaXtRk5", 772}, 
{"1p7UUdjKLqZXmX9CN9BT6ziXwEB7so1d3", 771}, 
{"1HhXp81sBUkkevnaFue5sLF3PX91rKhajo", 766}, 
{"1MPqyixDXSmS4zqEXqFpEozn7MiP3aNXnV", 765}, 
{"3M9f7UUhBEyicXBo7zkMyYPYZdyFkmRc72", 764}, 
{"13AB46g9q6QjMjJoCGetwLDgWW7M5xXeT8", 760}, 
{"39h1qcQJ2RsfFL99LvMttr87HYMecRJ4mc", 760}, 
{"15z9buAT4fFKkQVLkpAwxPzLVMc9Goi4ps", 757}, 
{"1C6k1x4e8seBvmD79uE5LXyd7ybGJDUDG2", 757}, 
{"1FhsNEonqwkubkQrkQyd8xEKLJB94P4paV", 754}, 
{"1NmuQ93ZEJ1hh1BBDeSp1ejFgbHKjefGuM", 754}, 
{"17een9mHPisP6z24wdXVDBvWosxeC2kAhX", 754}, 
{"1ARf1Np1PY54qbtdT5oik3ixrfNuVpvTgc", 750}, 
{"15UkFYLMs5nytwiKWqGgkkVo1fjLFAeJhs", 750}, 
{"1HCHzPzSMDwnhLZAg9KA6LpfTo8wKLVxjd", 750}, 
{"34QqHcTRAB5ujVfitWaifHj7GRdKGqd3Ey", 750}, 
{"1QGzf5hAFtaLvjAcMJysiiDnC54wzowaTW", 750}, 
{"3QGjYW5h2M5NCZb1ddmd3595752gDMkBcw", 750}, 
{"1AXYag6VRhzJLuKZroEetC5sxGiSMqYR9x", 745}, 
{"1AVuzuudoRz9sJBf2cSjnWVPBdQCCtgWXF", 742}, 
{"3PkMJcmmX5SZSP6aUxXYCJdzqzeUvLhb5H", 741}, 
{"176xp6z2xxGwViyN1iu2YQ96JL85wjqScv", 740}, 
{"18XVaufSHDd6cbMvpWY8XWUKhYMniHZ1S9", 739}, 
{"1NAaDwh8GoVkfVwKJ6FfiYFWLw6bqq65wF", 735}, 
{"328Zkzru37EmRC5FtR6krGM9wjhqoJFr7r", 734}, 
{"17mxawNmRXVAuHpBnikiZiP35n7th9zVcX", 733}, 
{"1DkqP37kbaEXGXVMsMvNcbC81fAne8sV5s", 733}, 
{"3C2fqTniaYtHK7sMZnq4px1DbGt3yT4PP5", 728}, 
{"1EChWw6qrQNezbwcRAVWxKN3iAiNcqxu8z", 726}, 
{"1UaPw3y6V5cQSjKhCocUKSLDgyABwgJ8T", 725}, 
{"1JZgoYgVYRNqSNLbRjq9E9Pwj8LNvHiNGH", 724}, 
{"1yAFU3dLJEzUch7b4rgZV6bnkRKEe1Fu9", 721}, 
{"1AWqYR4CCP5j9GEqMNk8b3ZNPPfG5Jniu1", 721}, 
{"18ihEZW4jPWkFkMmhWHYWDtUUa7ZWMUaGy", 720}, 
{"12zcaKwPrGuSmESht1dufqvi2k4v7Z2vKG", 719}, 
{"3PKQu5W4TtWtwTXxMQDicpTLQR9XyjGiDc", 712}, 
{"bc1qpzlkeery6c7677wkjkela33vls7e6efrqnrq08", 712}, 
{"1GL6JssydA6ueTFAPJQ9DU8pfQMZA6tQTD", 707}, 
{"1Cx9fH7kg8rmWeM9o3oKghCWFrnSDwkLpk", 706}, 
{"1HemWKoEstRGsztA6JNEXNQARe89A6ncUY", 705}, 
{"1Jb6eDqrEzzDFD5muXi12et3hbY6AMjsbg", 701}, 
{"1Q138Xah26VDdPqZq1fJqz59iGdM4BUoPS", 701}, 
{"353aFQubAqke8JohZWHyFUAguWs9Ht1f2u", 700}, 
{"15Y7YTX7EQhgwPJ9hvDFw3Tfdh1kkFfbm6", 700}, 
{"16yzHwNdTfx6nh4cM3abTk9RJyVSRn9VCT", 700}, 
{"1Ht9usUwprHH33fr9Vrs2cryC1oPjtQ47M", 700}, 
{"1EsSSgpJorNT2mjCLn9PtyJt2DxrhBk5LV", 700}, 
{"1PU5g8Pgas6NXY27aW2ysonNKqCHs3oVFS", 700}, 
{"159U9EQWsp8H21dsDtZpLAuYAUJZ3YWgK4", 700}, 
{"3JZYVXhRkewhQUTySDVYPfo2RBWW4dFUhc", 700}, 
{"1AZ5VexBonz32Ah2VUHkbcppDX11XZN5R5", 700}, 
{"12DmyzYxw9nN6Q7FiGiTMf7WFUbVpWKvaU", 700}, 
{"1745G9XUHuSGZroA425RX9dhpVBB2hyWDh", 697}, 
{"18eTvCNYCmU7n73s5eHJZyPYVjLy2rfo4S", 697}, 
{"3JDdpSDkXM3tkB4N8JoNxakiQpjY7zDCGt", 695}, 
{"3BGykrN88NsyWrrMKfbLK5XqfkvfyTnohf", 693}, 
{"16tyEv1cKp6YFNQUGTep2Vys2yKjAEwiFF", 691}, 
{"125WeXgyrE4beiEeQewoaXf4H9BL5RiDoP", 691}, 
{"1PxHqff52QXBHxjrpJmC9p2GfqHXNMJ6aj", 690}, 
{"181bjuhNNAFnTx5tedjxTC4uUjXy48EfD2", 690}, 
{"1E6F83upBYtaU5haeeKaEbjCCs3vvRVQ6m", 688}, 
{"187fWXXULVecCmD32CQybbPu1ZigGoiVqV", 687}, 
{"12Ms4CPhyYThto9RfxsuiYKHFYMhaHyj1T", 685}, 
{"13qFdB4qMJV47jWk8osh8yFtYL2MaHRYWP", 685}, 
{"17qhg1xHJ1ckcXC56KUdGajQdgT1rLVmnZ", 684}, 
{"169pQKysziudrUWnDx3ppo4rhvY5QfTZ4C", 680}, 
{"17YVC4TUT3KH4QhaUqYDziGZcQm6a2EHBz", 677}, 
{"1P3ZZRVuVbgxGqnPo86k2QjTKpJwbVdBeu", 676}, 
{"12AoZzCLPzu6qgqpT8TyEMGCErXmDM37Cx", 675}, 
{"1NJgSVnHCcLr1op35jmg1HUJBKyZysadiz", 674}, 
{"1111111111111111111114oLvT2", 673}, 
{"33KqeQThCpV5zdfKpJhJEkRJ1fnNaE2iN2", 670}, 
{"18UWtv8nXZGo9NHkb36gTF26uwkRZW1oog", 670}, 
{"143xVSVXNNmTbvHz2zMV2ixW6hecY8eouH", 670}, 
{"1JdFaY9NTM8JRT3k7jaqeygJ3PtymFkTAA", 670}, 
{"3FcPQfjXqJF8kHYzXy2LiYHwZhjotKhBze", 670}, 
{"36LTBmmhifU3YnhEq8VurkT9GEF9nDxR3a", 670}, 
{"15A8UUzd1535v77fzM6egeZv3itSkKgoxJ", 669}, 
{"1CJdobMmZagcGYZwXxBgJd5WqZX8uPT6MT", 668}, 
{"1EZ4NRTG5fqC4wdtURQ7mVedb4cCeLsaXM", 668}, 
{"1GAeGGz1YPYkcz42ufFFcvhoaWLEFWeo6z", 668}, 
{"1FuRcaavsVibUULeFFkLe2ygAreAy7YL1c", 668}, 
{"1PrT8ZtBrhENbbxTMVx21HFuEcAK9JLjyc", 668}, 
{"1E7eQDxg6FMTdNiFSMP9f9TyRnuSn68FLY", 668}, 
{"1GbAoxxv5V6X22ASMY7Bjnb6wvkqaUETKE", 668}, 
{"12NwyPbJbSygBBVLb91mgsX3BGLcRNDrPU", 668}, 
{"1LKFRfgYijiq9yYn6yVYgW7nbnuMTGEkxf", 668}, 
{"1MuHgZf1MZBis639XZdFyGpoEWXP1ZpTHu", 668}, 
{"1Nq3799TDepeLP8CikLt1QyBsjhXzvaZ32", 668}, 
{"115QD9spBw4AFmat5xKXSHSiXQZYhcZNNb", 668}, 
{"1PJghZSZwWopgYWNWPPSXn1mV1UAkLuSXj", 665}, 
{"1GbgGnu3eanizm5Z1pPzYqDHNcZfobexeU", 664}, 
{"12dpzABdbKRg6Wc2yYtj29wqkxsFs75KVB", 663}, 
{"362r3B8qh533PBfdtzmaeaAZyTHd97XkHm", 660}, 
{"3DKyGo1gceRYGfGXwoBRZxG3WiajaZQQEQ", 660}, 
{"1HD2XyQRi6TxEQ93BB8cy1UeZNfSCPRWW", 658}, 
{"1Lpu1LJAhYTWLveYW5mwi9T2kF3NKWQcJP", 656}, 
{"17TzfAptkqVqakpiLPv5GSoWwa7tc3uaaA", 654}, 
{"12ftSLLqs3DTXLNP8mZ8j6zfBf6MTrnY3j", 654}, 
{"12YEZHpvn42dXnsbqa8psCfx8UcN5r7sPj", 653}, 
{"1gf3tuG33T2RDk6ZsjhK6FdS1cM5D67aA", 653}, 
{"3Lxs1kpNzMNeWZUoMRy2WfvJwcjjEuGyMM", 651}, 
{"1Pop2n8nQxAMzppNsLz56jUyQ3WASQpv7e", 651}, 
{"3JpEtJdMf2Qwjq776C7CygUp6fWGacRp7E", 651}, 
{"1CqDWA6SEziruw4muh55UdjbdApqs5j1Vp", 650}, 
{"17vYUwamwUkcwzWGgPNLAFjupSBFGWQRue", 650}, 
{"13bBu94gvcYLxG4L59daESBYEhrrgp2Xos", 650}, 
{"1B3NkzvEuJfqfh2vKaCkdA3XjXhH2bqQA3", 650}, 
{"3KnV7ZwBECjqH4G7khUfdUdZ8W4qK4RhEJ", 650}, 
{"16qWnv4yBzhnVHLBK68Btto93QgWgpbRiw", 649}, 
{"1LP44uaRgUyVvYhc2UBP2pmRX1bfa5Nv2P", 649}, 
{"3N4T3VkRqoDqPTvGSgLi1vxvCnnforXc5T", 647}, 
{"1LgGss5GEY1oxYaqrXTySJLGkZ8Z2TxJV4", 645}, 
{"1PCdUKiUTHMnK44mqdMBSmfcXP3ZoDheT2", 645}, 
{"31pHU1Hm6F1LA5f26xHv7sKjdGt3s5NtqB", 640}, 
{"33K6uZz91GH3VSy6RxVCA9DsmKNTfuGHxm", 639}, 
{"1P3So5oj86iBqwz9WLnmyXku9463Bah1cj", 639}, 
{"1QhUXUqmXo5BVLaKsLHx8DKYDiwtkgXbh", 638}, 
{"17UccxNRi6xg5y2GpPCDcXULwwpEJNEBkv", 636}, 
{"1PsgNxAC1stdDRo2VaFM6q8fmb1bQp2V8Z", 632}, 
{"1L4XEZ5x3wbgksa1K1VuP7ZtTzA1rXU3xq", 630}, 
{"1JH1qw4iMxhwrfBdmuBhGLUFRDrYJoQiJQ", 630}, 
{"18F64qHTWp8LDRrCtVWwDjHyMChv8rZCZV", 630}, 
{"3HzD3aVDkbjEgPUqDTdR2mYREFjKvQX8UL", 629}, 
{"1MdDjKmn9MmHThBVcHYsKrEtDZpg8Zmt6V", 628}, 
{"3MAwhzFBgVqVEpptBzGmwR2mkgDyxd6ST2", 626}, 
{"392HFJka5j2veMntA2gwyFN6Zy7Q5gr4AS", 625}, 
{"1CXgsYPq9MnCkGHo9oCu4gLopyyUbrDAXN", 624}, 
{"3DqsdMeJnh2VGBNrUNknFgAA5qg1qkf5yw", 624}, 
{"16oo3yybDrJrjnpME9ypmxuApBTFgQij36", 623}, 
{"3DkwUnNTVZTXNTJrmtPdyxe6e8t2f147ZX", 621}, 
{"15aCF6BWfgxyAYrKpYxGf2m2SS8PK1riSS", 620}, 
{"37bATF4kdvvfZF8Qe6oTAKerkhAC4j8SSN", 619}, 
{"34rVA4t651PGYUTe35QBEQoEHJpmGEwzy3", 614}, 
{"3Jhi9SbGUmxPAxEGvuoakgT614KkuN19AL", 613}, 
{"1NmzF5N79oaiCfSU6ghCDKWpM453LZ9WZo", 611}, 
{"1ENLWfW8jjQRWAyX4Qs3ZuLeyksEgjC8tW", 611}, 
{"1Gy1NjqQ2GqZDJteazHgqgL4WBUPFgfxrr", 610}, 
{"1DJja7qgy9fwhqSMgrLFTexMuCZbQjFeSs", 610}, 
{"1FxPujWkJE842LLuRsQFj5GMfbNFUfoftv", 607}, 
{"bc1qca08lln49typsgpr5cnn663akdutqhd6gqrxhqjyjytvyqhyrfjsjwsp76", 606}, 
{"13nhY2jDtXkewDb2GLKmtbBczhWDknsWMX", 606}, 
{"14Cx25XkprQCLqhhmgL3uriXb7aM7YTEXc", 606}, 
{"34EdPJ4Nc5ybGGTdC2uwrKXzAVnQpt4qaG", 604}, 
{"3HXQgC2kL6LsuHB2Sm1DuMRiuNY7EmgUav", 604}, 
{"3Pgu48RPeZE9NEpC3EtGLago5jKEwQmp8e", 603}, 
{"1ErMBJHFCmtawxCoVqNbUB8x2GVopFZiLW", 602}, 
{"1AdtaS6vGtUAEjrBoics9nEGixsUFi7vir", 601}, 
{"18GiSpLxugiHy5FsoYV3Ngeo1kme2rqhet", 600}, 
{"16MDruJJaKp7iTXmQ5npFYxyTLfyDEVXyh", 600}, 
{"1BU25ZQzxkJAQ7jVKBc7fBoJpPhHymbcWv", 600}, 
{"1JwcwrhedXg91p6Ffovn1XTJE9C63Ka2LG", 600}, 
{"1ABF1PwZTT4GZCdAPuHF9NSsy78ca2q3wW", 600}, 
{"1K6vURxUuK6uUCeXxk31PCyDahAu1raunh", 600}, 
{"1Bx8pSCW9Gzyvf1EjkeHJM5DpA3ip4At9h", 600}, 
{"1FXavuV1rjJicYau2md7pa22Q3P4HEcMLN", 600}, 
{"1J3CvmiBV9ic76bccSYDP5AL3AncScWTtK", 600}, 
{"1GqiJReJ1yMBUQyCNbM3apApTxk29S9QT8", 600}, 
{"19zkKsccBnwVbysbZsRNwo38ttPEkgFCT9", 600}, 
{"17m6n7SyEoZYFHBK4thVAAT6NAg1RSDT65", 600}, 
{"1Eqap1TvAFnebkH1TNEVdW3ZbGL27s91WV", 600}, 
{"3ApRTvbKv4TpAFHVWx72G1UgpPE8tejJjG", 600}, 
{"1DRQrN544QRz76o2GnCgVuqYyRbmxffvDp", 600}, 
{"3PJYiydMDxDkVsHRVVx1mpiHYEA1WLQ5Qi", 600}, 
{"1NVvGenw7BiwbUtj5yes1L5mA7nErfJyok", 600}, 
{"3QMc3Xk7CYmrL1qMBBCAbJQaiSFYTPgrAk", 600}, 
{"1ApdoCXWzzqbtJBLFDYdNUCcoxMMXvk4A8", 600}, 
{"1PyDmVAqBPo69JMCaMZXTnRa8zNYjwMr2J", 599}, 
{"3GTQSdr4iu19GzWg3Ph89YYEFFKnSHKjDv", 597}, 
{"18r1KRBaLQPcds2i15CwJAHPUYvNSW1gv7", 595}, 
{"1FqQ3BhmG532hV5s72W8Jm58wzmWkKzaNZ", 595}, 
{"1HP4w3YAym9sqpPkwyhLamexejeuzQjXx7", 591}, 
{"1L4FZa36xGvu4NSJ6BrTXg6HRJ5MFk9Hc4", 590}, 
{"13ygbLDjYAXtS5iUpVJ8xiGrkgt7FJCaVK", 589}, 
{"1YvCWqSpARRY7tyguMaPXHD9GCRyc74Hh", 589}, 
{"14AUXcL4RToUxVUCxinSS76JAs9C3Nhr7C", 587}, 
{"1494ntXqmjQJrmNdjtXaCYrugyjoqKTnsP", 587}, 
{"1GW7VX3mj6ms51biha6UZaybUpFWTjsfrJ", 587}, 
{"bc1qalwvk9m6c7ctgavwwzalf5jlx7r2jf6v8768pu", 586}, 
{"1E9GvhLfVYtJiq1f1Tc2xLHe9Dkd1Yymit", 586}, 
{"1AbYVWUqmpwTDMetWUiLmG5Xw1Pi1np8K2", 585}, 
{"3Hn1WNe8kYHBfPSwfPprXutTKNebtAcDdK", 584}, 
{"18v59dnWo91iqv2zQTZsTs6B4Kg83u1mtP", 584}, 
{"1Fk5fWfQY9hdPm8ZUuHNETHYHCZxadjgo6", 581}, 
{"1BYAc8qcAtVopKMjVUPUjEzSLtfxzvK5CG", 580}, 
{"3AGPnBasF6ZnHXbEay6PBdWXFc1JopiEmZ", 579}, 
{"1HZNsUqQxKVLmfPfCAzLwrnVDzx8CxwxnM", 576}, 
{"3D5MfZzwyF4rD263kFcCEunENYu9YEjoCR", 572}, 
{"1NreXnzuiQG4Wdam3KXK2dB8yEju5nXDWN", 572}, 
{"1PTAhbS2cefQTZKSA5drxVrPaTaqq2ciPQ", 572}, 
{"1Nd3dEzXj7diX6fj5CKjASSb214MXcgRaX", 571}, 
{"bc1q55xydh3ksazamr6mhrucseg5gultqepuh78v32", 570}, 
{"19etFF4h5rpodEtsru78EDMG1kcybbxKBS", 570}, 
{"1Aq35ge7hvtJkwEG62JZUuD6EL9okBAhki", 570}, 
{"1GkMebEsLSDg4Ewrj5HNM3VMLP9FYZaMCa", 570}, 
{"3HUxqdQmgDpvfxTJNgJWYDguVmN3DjbgY8", 569}, 
{"1ZhKkzRLLfpNGNHf8qDDH7uRZtaMue7tR", 568}, 
{"1khRNXx7SUGHEvcty7sHtWqk29jkC4mxW", 567}, 
{"1M8wTgPa9xP2FUfcs3cTrnx7WpKZACwZpS", 564}, 
{"14159SZynsvqo9mn9fEdpwFKWKL5HQuVGF", 563}, 
{"bc1qr2t46c80mdlujfdalf6zrn4hd3asze7cmzm0yw", 562}, 
{"14RG62RMPqY6wnFvMnf253D4BQPrFbcCcy", 562}, 
{"1MwtBfd83RB25y53L2S1hJWdMokE2AUUvZ", 560}, 
{"1DJrBUpy7zpcySbexeo3TJceRuAthcsiKQ", 559}, 
{"1Jf48wufcDpPQ2EEgX1jUULuTHVzDhqBSF", 557}, 
{"1KEBcwq7JzggrqdWYEZR1mK2787fiV8hnD", 556}, 
{"15peGup2HVXUYYdkFmiPLgmg8XX5Ex7jAS", 555}, 
{"1BQQUVgcUrSREw7h6cWQJXrqLYHpsF3hH7", 555}, 
{"3ENkv5HdUuZsLakZF3YbBjMgYPPeVkyqyd", 555}, 
{"1LiZMrHeFsbHtCK6coDvZenqyREPt5Q1Q", 554}, 
{"12yqLsUvrULLvejhJMWnTcEQ7xhHCoSEGC", 551}, 
{"3AMt3MngaLLFynRkbetGT9FpMFVft4Q2d9", 550}, 
{"1D2ASqRHaRJ8YNd2zhwbCq5DuRPdaetoQC", 550}, 
{"1DKAvDS4fVEKxJuC3yXkBfR5Y1awa9SFLi", 550}, 
{"15BKWJjL5YWXtaP449WAYqVYZQE1szicTn", 550}, 
{"16uwhx6EUMs8jTB3iQkfQgg3VXxqajzvEr", 550}, 
{"16wNiGSebSjTtaYqZdapiEoku1nQz2wA7A", 550}, 
{"1xYXK5k8f3YiMS7Z6u1Q1QhhYNpWazubs", 550}, 
{"14gHwHqxQHDkNkNejPufJ9bL3GqYS9tL9y", 550}, 
{"1Nhg39pb2UPCLZRGX3kRASvbs5PCGG7sCE", 550}, 
{"1HYfpwS9vyNFoCqnYHBSPQb3227GDBYS7B", 550}, 
{"1PRzWoDxpQNFXTHPMBK5ofpy2dZspgZuh9", 548}, 
{"1HDTTEDEe1WoPKG5hMNXujVQopBFqNXXCn", 548}, 
{"13irxVR7w6aWm7iFv16bPPe9MEfMBVu7ic", 548}, 
{"1HZq6emhXg991ypXZL7EAG5xJMUvte4Dyq", 546}, 
{"3CYRFUqKArjmwMNsDivTCggbiZHUSCygJn", 545}, 
{"3JgxtnWmACSuggPqigW6i5X8sJzijfZ5wX", 544}, 
{"19bFYeY3yEqctMWTLAFQHgEtq6KuDveew7", 544}, 
{"3FfwXR52Jj5CLRowmvyd71b3mn6HFssFSP", 540}, 
{"33QL72BbZfXkjj9wdkbKAEFWTZCkKUqdS3", 540}, 
{"14hwhtzdABhPWejrMYGW7gLv1ZtDtqvNTj", 536}, 
{"1PqHkiqHDpgEDTfQmYo1VxvuHfjoggfCqK", 535}, 
{"1MeTgxWJvKNwcxCVfdehRCW8fy1RSBBjyF", 534}, 
{"1Mvb7gRsmx71qyrujh1NezQabdQKnfdTxs", 534}, 
{"128Ksg2S84u7x9VTRgAerrJXPCt3XpXr24", 534}, 
{"1GiDaFZMYAKmrtehaV8fRxVVrKggaqj7aY", 531}, 
{"1PHpCrNnA8QYUobaGiWg1ZYw4hr35CwXHz", 530}, 
{"1Pe4tWa5UCVGTuW6drdjDdCnARtRPAN7jp", 529}, 
{"1QBHX5fgDgjJraTzP9vFLdDWuKRugzW6Mk", 528}, 
{"1ALv7TiG5xGC2WrsYVdVhsqaPrSVgy4W14", 528}, 
{"1JGwfqPTJHgLH4jYeK1x2ERSJf74YT8WSb", 528}, 
{"194Wx1fHfqscz6JfAt9H8wRpXTUwfyXYU2", 528}, 
{"13mX2fZ1jyzLm4HRkQUofUv3ZSSatUQE2T", 528}, 
{"12Kfr7FK445ocL1QSsALXBiUe4N7V4R8aW", 528}, 
{"1Fecr5XAKmXJ8xX6qwrE7toSZx9X6nbj1J", 528}, 
{"1HPKKxuv1AmkqEBhrRY7HxQ9wfd6GPEamx", 528}, 
{"3Gvnv3EuVfU7VgwGULcysx9YGuEYazckEY", 525}, 
{"3MEtun5DBL5gPMUm8VJUJv7yeZCVQKcw8k", 525}, 
{"3LpExEGoRGgxKWyC3fxCx972564v5gVSGp", 523}, 
{"1GzUm2U7s2fXEHjEgMUfg4P5X81VhNVQKv", 520}, 
{"1MMdcKt86PDQwqTmJbt81NpDyTPcfWpEaF", 520}, 
{"391ZrQjA7jCRTHWgjWXWoLYa2uiF75FtXX", 520}, 
{"1LRHPN36YQufar8gH4au2evXLeD5ddPJwY", 520}, 
{"1LQt5LCM8Tvr9Tzua8koC1CVwuJrSoDsd2", 519}, 
{"1D6nQmJAB6DzrfNCXMCkS1brWFS6uTq7ah", 518}, 
{"3KetLPmh4j4CdTqy1evqvZdWufx3b2pRxH", 517}, 
{"35mfoF97ytoqMdNTJGcHvAYrHsFCird8zC", 516}, 
{"1LDSEFMq5q7AQA8oVDv9ysigBrLmDMXVKs", 516}, 
{"13n9WxvfwBqFqfRoUJEUAAGG2CRbKN9pzJ", 514}, 
{"13oTycJRBJHtkfXKYuDXpWTKM6FZNzKwrh", 514}, 
{"39WaBZFbTF5UYMWypUR38fMXsvdc47x8cs", 513}
};

const size_t bitcoinListSize = sizeof(bitcoinList) / sizeof(bitcoinList[0]);

// Функция для поиска числа по Bitcoin-адресу
int getBitcoinValue(const String &address) {
  for (size_t i = 0; i < bitcoinListSize; i++) {
    // Сравниваем входной адрес со строкой из массива
    if (address.equals(String(bitcoinList[i].address))) {
      return bitcoinList[i].value;
    }
  }
  // Если адрес не найден, можно вернуть 0 или другое значение по умолчанию
  return 0;
}


// Конец функции лотерейного поиска
//====================================================================================

void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(A0));
  pinMode(LED_BUILTIN, OUTPUT); // Устанавливаем встроенный светодиод как выход
  digitalWrite(LED_BUILTIN, HIGH); // Выключаем светодиод  (инверсная логика)
  pinMode(LED_PIN_RED, OUTPUT); // Устанавливаем пин D13 как выход
  pinMode(LED_PIN_YELLOW, OUTPUT); // Устанавливаем пин D12 как выход
  pinMode(LED_PIN_GREEN, OUTPUT); // Устанавливаем пин D11 как выход
  digitalWrite(LED_PIN_RED, LOW);  // Выключаем светодиод
  digitalWrite(LED_PIN_YELLOW, LOW);  // Выключаем светодиод
  digitalWrite(LED_PIN_GREEN, LOW);  // Выключаем светодиод
  delay(1000);
      /*
        uint8_t privateKey[32];
        uint8_t publicKey[65];  // 65 байт: 0x04 + 32 байта X + 32 байта Y
        String PrK="";
        String PuK="";
        generatePrivateKey(privateKey);
        digitalWrite(LED_PIN_RED, HIGH);
        String btcAddress = publicKeyToBitcoinAddress(PuK);
        Serial.print("Bitcoin Address=");
        Serial.println(btcAddress);
        digitalWrite(LED_PIN_YELLOW, HIGH);
        // Накопление строки для приватного ключа (если нужно)
        for (int i = 0; i < 32; i++) {
          char buf[3]; // 2 символа для числа и 1 для '\0'
          sprintf(buf, "%02X", privateKey[i]);
          PrK += buf;
        }
        // Накопление строки для публичного ключа
        for (int i = 0; i < 65; i++) {
          char buf[3];
          sprintf(buf, "%02X", publicKey[i]);
          PuK += buf;
        }
          
          Serial.print("Private Key=");
          Serial.println(PrK);
          Serial.print("Public Key=");
          Serial.println(PuK);
          digitalWrite(LED_PIN_GREEN, HIGH);
          delay(3000); 
          digitalWrite(LED_PIN_RED, LOW);  // Выключаем светодиод
          digitalWrite(LED_PIN_YELLOW, LOW);  // Выключаем светодиод
          digitalWrite(LED_PIN_GREEN, LOW);  // Выключаем светодиод
      */   
}

void loop() {
  uint8_t privateKey[32];
  uint8_t publicKey[65];  // 65 байт: 0x04 + 32 байта X + 32 байта Y
  String PrK="";
  String PuK="";
  
  generatePrivateKey(privateKey);
  getPublicKey(privateKey, publicKey);

  if (getPublicKey(privateKey, publicKey)) {
        
// Накопление строки для приватного ключа (если нужно)
for (int i = 0; i < 32; i++) {
  char buf[3]; // 2 символа для числа и 1 для '\0'
  sprintf(buf, "%02X", privateKey[i]);
  PrK += buf;
}

// Накопление строки для публичного ключа
for (int i = 0; i < 65; i++) {
  char buf[3];
  sprintf(buf, "%02X", publicKey[i]);
  PuK += buf;
}
    ///
    Serial.print("Private Key=");
    Serial.println(PrK);
    Serial.print("Public Key=");
    Serial.println(PuK);
    ///
    String btcAddress = publicKeyToBitcoinAddress(PuK);
    ///Serial.print("Bitcoin Address=");
    Serial.println(btcAddress);

    int value = getBitcoinValue(btcAddress);
    /*
    Serial.print("Значение для адреса ");
    Serial.println(value);
    Serial.println();
    */
      if (value>0){
       m1: 
        digitalWrite(LED_BUILTIN, LOW);  // Включаем светодиод (инверсная логика)
        Serial.println("Win =!!!= ");
        Serial.print("Win Private Key = ");
        Serial.println(PrK);
        Serial.print("Win Public Key = ");
        Serial.println(PuK);
        Serial.print("Win Bitcoin Address = ");
        Serial.println(btcAddress);
        delay(2000); 
        digitalWrite(LED_BUILTIN, HIGH); // Выключаем светодиод  (инверсная логика)
        delay(2000); 
       goto m1; 
      }

  } else {
    Serial.println("Ошибка генерации публичного ключа");
  }
  

delay(3);  
}
