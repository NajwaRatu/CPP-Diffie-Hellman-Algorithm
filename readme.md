> g++ -o server server.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -Wno-deprecated-declarations

> ./server

> g++ -o client client.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -Wno-deprecated-declarations

> ./client

Klien dan server menggunakan algoritma Diffie-Hellman (DH) untuk membuat key bersama tanpa harus saling berbagi key sebelumnya. Setelah key terbentuk, dapat menggunakan algoritma AES dalam mode CBC (Cipher Block Chaining) untuk mengenkripsi pesan-pesan yang dikirimkan.

Diffie-Hellman (DH): Algoritma yang memungkinkan klien dan server untuk menciptakan kunci rahasia bersama meskipun komunikasi dilakukan melalui jaringan yang tidak aman. Ini memungkinkan mereka membuat "shared secret" (kunci bersama) yang hanya diketahui oleh kedua pihak.
AES dengan Mode CBC: AES adalah algoritma enkripsi, dan mode CBC menggunakan IV untuk memastikan setiap pesan terenkripsi terlihat unik, bahkan jika isinya sama.

Keamanan
Dengan metode ini, klien dan server bisa bertukar pesan tanpa harus berbagi kunci sebelumnya. Jika ada yang menyadap komunikasi mereka, penyadap tidak akan bisa membaca pesan karena tidak memiliki kunci rahasia yang dipakai untuk enkripsi.
