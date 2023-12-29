# Toy java crypto client & server
## <span style="color: orange;">:warning: Known issues</span>
In Diffie Hellman context, when a c/c++ client uses i2d_PUBKEY* to get his/her public key then sends it to a java server, the java server would parse that public key **unsuccessfully**. It seems like java only understands PKCS#3 as the standard for peer's public key, but i2d_PUBKEY* produces one in ANSI X9.42 standard.
