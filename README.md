NOTICE:

It requires OPENSSL.NET to run, so please don't change the Pre-Build Events in your visual studio!


 - "Warcraft 3 Map.pem" is a 2048bit RSA public key from Blizzard, can be used to verify all Blizzard's Maps.

 -"Nirvana Map.pem" is a custom public key, used to verify Maps that are made for the Nirvana.

 - In order to use the 'Sign Map' feature, you first need to generate your own 2048bit RSA private key(in pem format) and replace the data in your game.dll with the corresponding public key.(The replacing tool will be released shortly.)


 - Build in .Net 3.5, VS 2010

=====================================================

- A brief description about how this thing works -

(...)