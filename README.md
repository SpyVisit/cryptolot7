# cryptolot7
Written in C++ for Arduino, it generates private and public keys, encodes them into Bitcoin addresses, and checks for associated values. LEDs provide visual feedback, serving as an educational tool for cryptography.

This code is an analogy to a crypto lottery, which has a negligible but existent chance of guessing the private key of Bitcoin addresses from a list of abandoned ones. It is written in C++ for the Arduino platform and performs several functions related to generating Bitcoin addresses and searching for values associated with those addresses.

### Functionality of the Code:

1. **Generation of Private and Public Keys**:
   - The function `generatePrivateKey(uint8_t *privateKey)` creates a random 32-byte private key.
   - The function `getPublicKey(const uint8_t *privateKey, uint8_t *publicKey)` computes the public key based on the private key.

2. **Encoding the Public Key into a Bitcoin Address**:
   - The public key is hashed using SHA-256 and RIPEMD-160 algorithms to obtain a Bitcoin address in Base58 format. This is implemented in the function `publicKeyToBitcoinAddress(String pubKeyHex)`.

3. **Searching for Values for Bitcoin Addresses**:
   - There is an array `bitcoinList` that stores known Bitcoin addresses and their corresponding values (the amount of bitcoins).
   - The function `getBitcoinValue(const String &address)` searches for the value associated with a given address, returning the amount of bitcoins or 0 if the address is not found.

4. **Setting Up LED Indicators**:
   - Three LEDs (red, yellow, and green) are used for visual indication of status (e.g., successful key generation or a win).

5. **Main Loop Operation**:
   - In the `loop()` function, private and public keys are generated. If the public key is successfully generated, the corresponding Bitcoin address is computed.
   - Then, a search for the value associated with that address is performed. If the value is greater than 0, an LED lights up, and information about the winning keys and address is displayed.

6. **Use of Libraries**:
   - The code utilizes the `uECC` library for working with elliptic curves and the `SHA256` library for computing hashes.

### Conclusion
The code serves as a foundation for creating a simple Bitcoin address generator with the ability to check for the presence of bitcoins at those addresses. This can be useful for learning the basics of cryptography and working with Bitcoin technologies.
