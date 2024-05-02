"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const { Console } = require("console");


/********* Implementation ********/
class Keychain {
  
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Return Type: void
   */
  constructor(aesKey, hmacKey, iv) {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
         //master salt is the salt used to generate key material from plaintext pass for aes/hmac key
         masterSalt: iv,
         //salts is a dictionary of salts used for encrypting each password stored
         salts: {}
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
         aesKey: aesKey,
         hmacKey: hmacKey
    };
    this.kvs = {}

    this.data.version = "CS 255 Password Manager v1.0";
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;
  };

  /** 
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    let iv = genRandomSalt();
    //password generates 2x keys: 1 for aes encryption and one for mac'ing
    let keys = await Keychain.generate_keys(password, iv)
    return new Keychain(keys[0], keys[1], iv);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    let newObj = JSON.parse(repr);
    let newkeys = await Keychain.generate_keys(password, newObj.data.masterSalt)  
    let keychain = await new Keychain(newkeys[0], newkeys[1], newObj.data.masterSalt);
    
    //compare trusted data check to ensure repr was not tampered with
    let macVerify = await subtle.verify("HMAC",keychain.secrets.hmacKey,trustedDataCheck,repr)

    if(macVerify){
      //Restore data/kvs from original object - secrets should not have been published
      keychain.data = JSON.parse(JSON.stringify(newObj.data))
      keychain.kvs = JSON.parse(JSON.stringify(newObj.kvs))
      return keychain;

    }else{
      throw "KVS Integrity Error"
    }
  };

  /**
    * Returns a JSON serializati-on of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * Return Type: array
    */ 
  async dump() {
    if (this.kvs != undefined){
      //Explicitly removing secrets from output
      let thisCopy = JSON.parse(JSON.stringify(this));
      thisCopy.secrets = {};
      //Flatten object and create mac tag
      let content = JSON.stringify(thisCopy);
      let checksum = await subtle.sign("HMAC",this.secrets.hmacKey, content);

      return [content, Buffer.from(checksum)];
    }
    else
      return null;
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    //lookup using hmac name tag
    let hmacName = await subtle.sign("HMAC",this.secrets.hmacKey, name);
    hmacName = Buffer.from(hmacName).toString();

    if (typeof(this.kvs[hmacName]) == "undefined"){
      return null;
    }
    else {
      let iv = this.data.salts[hmacName]
      let encryptedValue = this.kvs[hmacName]
      let decryptValue = await Keychain.decrypt_string(Buffer.from(encryptedValue), this.secrets.aesKey, iv)
      return Buffer.from(decryptValue).toString();
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    //add to dict using hmac name tag
    let hmacName = await subtle.sign("HMAC",this.secrets.hmacKey, name);
    hmacName = Buffer.from(hmacName).toString();
    
    let iv = genRandomSalt();
    let encryptedValue = await Keychain.encrypt_string(value, this.secrets.aesKey, iv);

    //store random salt used for password encryption in salts dict
    this.data.salts[hmacName] = iv
    this.kvs[hmacName] = encryptedValue
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    //lookup via hmac name tag
    let hmacName = await subtle.sign("HMAC",this.secrets.hmacKey, name);
    hmacName = Buffer.from(hmacName).toString();

    if (typeof(this.kvs[hmacName]) == "undefined")
    return false;
  else
    delete this.kvs[hmacName];
    return true;
  };
  
  static get PBKDF2_ITERATIONS() { return 100000; }

  static async generate_keys(password, iv){
    let keyMaterial = await subtle.importKey("raw",password,"PBKDF2",false,["deriveKey"]);
    let basekey =await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: "hmac", 
        iterations: Keychain.PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "HMAC", hash:"SHA-256", length:256},
      true,
      [ "sign", "verify" ]
    );

    //generate new key material to introduce entropy and sepparate subkeys from plaintext password
    let hmacKeyMaterial = await subtle.sign("HMAC", basekey, "HMAC")
    let aesKeyMaterial = await subtle.sign("HMAC", basekey, "AES")
    let aesKey = await subtle.importKey("raw",aesKeyMaterial,"AES-GCM",false,["encrypt", "decrypt"]);
    let hmacKey = await subtle.importKey("raw",hmacKeyMaterial,{ name: "HMAC", hash:"SHA-256"},false,["sign","verify"]);

    return [aesKey, hmacKey];
  }

  static async encrypt_string (inputStr, key, iv){
    //wrapper for subtle.encrypt
    let ciphertext =  await subtle.encrypt(
        {
        name: "AES-GCM",
        iv:iv,
        },
        key,
        inputStr
    );
    return Buffer.from(ciphertext);

  }

  static async decrypt_string(inputStr, key, iv){
    //wrapper for subtle.decrypt
    let plaintext = "";
    try{
        plaintext = await subtle.decrypt(
        {
            name: "AES-GCM",
            iv:iv,
        },
        key,
        inputStr
        );
    }
    catch(err){
        console.log(err)
    }
    return Buffer.from(plaintext).toString();  
}
};

module.exports = {
  Keychain: Keychain
}