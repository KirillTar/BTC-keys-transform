Для разработки использовалась IDE Microsoft Visual Studio 2019, стандарт языка C++17, библиотека OpenSSL.
Для преобразования строки в HEX-формат использовалась функция sha256.
Преобразования закрытого ключа (HEX) осуществлялись пошагово, как на этом сайте: https://secretscan.org/PrivateKeyWif

Например, для преобразования HEX->WIF:
1)Префикс 80 + закрытый ключ.
2) Два раза пропускаем строку через sha256, берем первые 8 символов – получаем контрольную сумму.
3)Объединяем шаги 1 и 2 (checksum как суффикс) -> кодируем с помощью алфавита Base58.

Преобразование HEX->P2PKH:
1) Получаем публичный ключ из закрытого (с помощью функционала OpenSSL). В зависимости от того, сжатый ключ или нет – получаем сжатый/несжатый адрес P2PKH.
2) Хэшируем через sha256
3) Хэшируем через hash160 (RIPEMD160), добавляем префикс 00, суффикс контрольной суммы, как в предыдущем примере
4) Снова кодируем в Base58.

P2SH в целом, использует те же шаги, что и P2PKH, но с BECH32 преобразование немного сложнее:
1) Используем сжатый публичный ключ (начинается с 02/03), хэшируем его через sha256, hash160.
2) Затем, используя 20-байтную выходную последовательность, преобразуем числа в 5-байтные:
https://en.bitcoin.it/wiki/Bech32

"e.g. 751e76e8199196d454941c45d1b3a323f1433bd6 ->
The result of step 3 is an array of 8-bit unsigned integers (base 2^8=256) and Bech32 encoding converts this to an array of 5-bit unsigned integers (base 2^5=32) so we “squash” the bytes to get:
in hex: 0e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16"
in numbers: 14 20 15 07 13 26 00 25 18 06 11 13 08 21 04 20 03 17 02 29 03 12 29 03 04 15 24 20 06 14 30 22
5 bits binary: 01110 10100 01111 00111 01101 11010 00000 11001 10010 00110 01011 01101 01000 10101 00100 10100 00011 10001 00010 11101 00011 01100 11101 00011 00100 01111 11000 10100 00110 01110 11110 10110
4) Добавляем бит версии 00, как префикс
5) Дальше следующий шаг:
"Compute the checksum by using the data from step 5 and the H.R.P (bc for MainNet and tb for TestNet) 0c0709110b15"

Контрольная сумма у bech32 своя, ее вычисление можно взять из github’a bech32: 
https://github.com/sipa/bech32/blob/master/ref/c%2B%2B/bech32.cpp
6) Добавляем полученную контрольную сумму к шагу 3, как суффикс
7) Полученную строку маппим на символы bech32 (qpzry9x8gf2tvdw0s3jn54khce6mua7l)
8) Добавляем HRP – bc и разделитель – 1

![image](https://github.com/user-attachments/assets/02bea32d-e835-47af-bd65-d6a39fb692ea)
