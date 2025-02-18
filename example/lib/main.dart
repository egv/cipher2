import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:cipher2/cipher2.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _plainText = 'Unknown';
  String _encryptedString = '';
  String _decryptedString = '';

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    String encryptedString;
    String plainText = '我是shyandsy，never give up man';
    String key = 'xxxxxxxxxxxxxxxx';
    String iv = 'yyyyyyyyyyyyyyyy';
    String decryptedString;

    // test
    await testEncryptAesCbc128Padding7();

    await testDecryptAesCbc128Padding7();

    await testEncryptAesGcm128(); // GenerateNonce();

    try {
      // encrytion
      encryptedString =
          await Cipher2.encryptAesCbc128Padding7(plainText, key, iv);

      // decrytion
      //encryptedString = "hello";
      decryptedString =
          await Cipher2.decryptAesCbc128Padding7(encryptedString, key, iv);
    } on PlatformException catch (e) {
      encryptedString = "";
      decryptedString = "";
      print("exception code: " + e.code);
      print("exception message: " + e.message);
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      _plainText = plainText;
      _encryptedString = encryptedString;
      _decryptedString = decryptedString;
    });
  }

  void testEncryptAesCbc128Padding7() async {
    // case 1： wrong length on key
    String plainText = '我是shyandsy，never give up man';
    String key = 'xx';
    String iv = 'yyyyyyyyyyyyyyyy';
    String encryptedString = "";

    try {
      // encrytion
      encryptedString =
          await Cipher2.encryptAesCbc128Padding7(plainText, key, iv);
      print("testEncrytion case1: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_KEY_OR_IV_LENGTH") {
        print("testEncrytion case1: pass");
      } else {
        print("testEncrytion case1: failed");
      }
    }

    // case 2： wrong length on iv
    plainText = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyy';
    encryptedString = "";

    try {
      // encrytion
      encryptedString =
          await Cipher2.encryptAesCbc128Padding7(plainText, key, iv);
      print("testEncrytion case2: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_KEY_OR_IV_LENGTH") {
        print("testEncrytion case2: pass");
      } else {
        print("testEncrytion case2: failed");
      }
    }

    // case 3: null data
    plainText = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyy';
    encryptedString = "";

    try {
      // encrytion
      encryptedString = await Cipher2.encryptAesCbc128Padding7(null, key, iv);
      print("testEncrytion case3: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_PARAMETER_TYPE") {
        print("testEncrytion case3: pass");
      } else {
        print("testEncrytion case3: failed");
      }
    }

    // case 4: null key
    plainText = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyyyyyyyyyyyyyyy';
    encryptedString = "";

    try {
      // encrytion
      encryptedString =
          await Cipher2.encryptAesCbc128Padding7(plainText, null, iv);
      print("testEncrytion case4: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_PARAMETER_TYPE") {
        print("testEncrytion case4: pass");
      } else {
        print("testEncrytion case4: failed");
      }
    }

    // case 5: null iv
    plainText = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyyyyyyyyyyyyyyy';
    encryptedString = "";

    try {
      // encrytion
      encryptedString =
          await Cipher2.encryptAesCbc128Padding7(plainText, key, null);
      print("testEncrytion case5: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_PARAMETER_TYPE") {
        print("testEncrytion case5: pass");
      } else {
        print("testEncrytion case5: failed");
      }
    }
  }

  void testDecryptAesCbc128Padding7() async {
    // case 1： wrong length on key
    String encryptedString = '我是shyandsy，never give up man';
    String key = 'xx';
    String iv = 'yyyyyyyyyyyyyyyy';
    String plainText = "";

    try {
      // encrytion
      plainText =
          await Cipher2.decryptAesCbc128Padding7(encryptedString, key, iv);
      print("testDecrytion case1: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_KEY_OR_IV_LENGTH") {
        print("testDecrytion case1: pass");
      } else {
        print("testDecrytion case1: failed");
      }
    }

    // case 2： wrong length on iv
    encryptedString = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyy';

    try {
      // encrytion
      plainText =
          await Cipher2.decryptAesCbc128Padding7(encryptedString, key, iv);
      print("testDecrytion case2: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_KEY_OR_IV_LENGTH") {
        print("testDecrytion case2: pass");
      } else {
        print("testDecrytion case2: failed");
      }
    }

    // case 3: null data
    encryptedString = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyy';

    try {
      // encrytion
      plainText = await Cipher2.decryptAesCbc128Padding7(null, key, iv);
      print("testDecrytion case3: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_PARAMETER_TYPE") {
        print("testDecrytion case3: pass");
      } else {
        print("testDecrytion case3: failed");
      }
    }

    // case 4: null key
    encryptedString = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyyyyyyyyyyyyyyy';

    try {
      // encrytion
      plainText =
          await Cipher2.decryptAesCbc128Padding7(encryptedString, null, iv);
      print("testDecrytion case4: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_PARAMETER_TYPE") {
        print("testDecrytion case4: pass");
      } else {
        print("testDecrytion case4: failed");
      }
    }

    // case 5: null iv
    encryptedString = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyyyyyyyyyyyyyyy';

    try {
      // encrytion
      plainText =
          await Cipher2.decryptAesCbc128Padding7(encryptedString, key, null);
      print("testDecrytion case5: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_PARAMETER_TYPE") {
        print("testDecrytion case5: pass");
      } else {
        print("testDecrytion case5: failed");
      }
    }

    // case 6: data
    encryptedString = '我是shyandsy，never give up man';
    key = 'xxxxxxxxxxxxxxxx';
    iv = 'yyyyyyyyyyyyyyyy';

    try {
      // encrytion
      plainText =
          await Cipher2.decryptAesCbc128Padding7(encryptedString, key, iv);
      print("testDecrytion case6: failed");
    } on PlatformException catch (e) {
      encryptedString = "";
      if (e.code == "ERROR_INVALID_ENCRYPTED_DATA") {
        print("testDecrytion case6: pass");
      } else {
        print("testDecrytion case6: failed");
      }
    }
  }

  void testEncryptAesGcm128() async {
    String nonce = "VXZ0U3VwcVVwN1E0";
    GcmResult encryptionResult;
    String plaintext = "7dFO+fEizmFMTiL+UJAadDCgovGQyLBiGMVViT4MVs4=";
    String key = Base64Encoder().convert(sha256
        .convert(utf8.encode(
            "Vu8gU4Z898vm2WEoGCGzCJ@J6gConDJM9ca583658bce4c00b19b3bb4a121d564"))
        .bytes);
    String result = "";
    String additionalData = "VXZ0U3VwcVVwN1E0ZBayvQ==";
/*
key "Vu8gU4Z898vm2WEoGCGzCJ@J6gConDJM9ca583658bce4c00b19b3bb4a121d564"
priv "7dFO+fEizmFMTiL+UJAadDCgovGQyLBiGMVViT4MVs4="
pub "VXZ0U3VwcVVwN1E0ZBayvQ=="
nonce "VXZ0U3VwcVVwN1E0"
*/

    try {
      encryptionResult = await Cipher2.encryptAesGcm128(
        plainText: plaintext,
        key: key,
        nonce: nonce,
        additionalData: additionalData,
      );
      print(nonce);
      print(encryptionResult.result);
      print(encryptionResult.tag);

      print("testEncryptAesGcm128 case1: pass");
    } on PlatformException catch (e) {
      print("testEncryptAesGcm128 case1: failed, " + e.code);
    }

    try {
      result = await Cipher2.decryptAesGcm128(
        encryptedText: encryptionResult.result,
        key: key,
        nonce: nonce,
        additionalData: additionalData,
      );
      print(result);
      print("testEncryptAesGcm128 case2: pass");
    } on PlatformException catch (e) {
      print("testEncryptAesGcm128 case2: failed, " + e.code);
    }

    if (utf8.decode(Base64Decoder().convert(plaintext)) != result) {
      print("testEncryptAesGcm128 case3: failed");
    } else {
      print("testEncryptAesGcm128 case3: pass");
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
          backgroundColor: Colors.purple,
        ),
        body: Center(
          child: new ListView(
            children: <Widget>[
              new Container(
                child: Text(
                  'Orignal Text:',
                  style: TextStyle(
                      fontSize: 30.0,
                      fontWeight: FontWeight.bold,
                      color: Colors.white),
                ),
                decoration: new BoxDecoration(color: Colors.purple),
                padding: new EdgeInsets.fromLTRB(16.0, 16.0, 16.0, 16.0),
              ),
              new Container(
                child: Text(
                  _plainText,
                  style: TextStyle(fontSize: 20.0, color: Colors.black),
                ),
                padding: new EdgeInsets.fromLTRB(16.0, 16.0, 16.0, 16.0),
              ),
              new Container(
                child: Text(
                  'AES Encrytion Result:',
                  style: TextStyle(
                      fontSize: 30.0,
                      fontWeight: FontWeight.bold,
                      color: Colors.white),
                ),
                decoration: new BoxDecoration(color: Colors.purple),
                padding: new EdgeInsets.fromLTRB(16.0, 16.0, 16.0, 16.0),
              ),
              new Container(
                child: Text(
                  _encryptedString,
                  style: TextStyle(fontSize: 20.0, color: Colors.black),
                ),
                padding: new EdgeInsets.fromLTRB(16.0, 16.0, 16.0, 16.0),
              ),
              new Container(
                child: Text(
                  'AES Decrytion Result:',
                  style: TextStyle(
                      fontSize: 30.0,
                      fontWeight: FontWeight.bold,
                      color: Colors.white),
                ),
                decoration: new BoxDecoration(color: Colors.purple),
                padding: new EdgeInsets.fromLTRB(16.0, 16.0, 16.0, 16.0),
              ),
              new Container(
                child: Text(_decryptedString,
                    style: TextStyle(fontSize: 20.0, color: Colors.black)),
                padding: new EdgeInsets.fromLTRB(16.0, 16.0, 16.0, 16.0),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
