# uicc-kic-opc

Demonstrates 
* How to decrypt a KIc, and generate an OPc
* How to encrypt a KI

We will use the CBC mode as [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).

## Install

```bash
❯ cpan Crypt::Mode::CBC
```

## Run

```bash
❯ cd examples

❯ ./decode_kic.pl
KIc = FBE8C170F6A5C6C257E5324719674818, KI = DD07DF0AA9CF5C03464C8639B28563E3, OPc = B79844F722C8A9F8BD86D000CA14E6A1

❯ ./encode_ki.pl
KI = 8978B79E7C104F678FA5C336509DB188, KIc = 45D413C2D928423EAB80AC61F2C3D5A0
```
