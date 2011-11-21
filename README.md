This pretends to be a Messaging Platform.

Aim
===

This pretends to be a way to provide a cryptographically-secure end-to-end method of sending instant messages.

At this very moment, we aim to generate messages to be saved locally and read locally.
Transmission of the messages is itself simple, as we could use, potentially, any online provider.

Description
===========

This is a proof of concept, and eventually will become a Browser Extension, in order to try to avoid potential problems such as MITM attacks on the server-returned JavaScript code.

The coder is aware that JavaScript code like this should never be transmitted through insecure protocols (as this would allow manging of the cryptographic routines) and encourages the use of this software in a local fashion.

The webpage should be served locally, without potential MITM attacks and the crypto code should never be looked for in the outside.

However, storing of the keys could be done outside your own computer (provided they were also cyphered, with AES, for example).


Anyway, this is a proof of concept and anyway is free to give suggestions :)

