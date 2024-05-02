# Secure-Password-Manager

In this repository, I developed a secure password manager which involved implementing cryptographic primitives like authenticated encryption and hash functions using the SubtleCrypto library. My solution utilized a key-value store to securely manage passwords, encrypting each entry individually with AES-GCM to ensure confidentiality and integrity. 

To prevent information leakage about stored domains, HMAC of each domain name was used as keys instead of storing the names directly. Additionally, I incorporated defenses against swap attacks by verifying the integrity of the password database using a SHA-256 checksum. I employed PBKDF2 for deriving keys from a master password, ensuring resistance against brute-force attacks. 

The implementation covered various API functions for initialization, loading, storing, retrieving, and removing entries, with runtime complexities specified. Overall, my approach aimed to provide a robust and efficient password management solution while addressing potential security threats outlined in the assignment's threat model.
