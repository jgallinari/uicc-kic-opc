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
❯ ./decode_kic.pl
KIc = FBE8C170F6A5C6C257E5324719674818, KI = 8978B79E7C104F678FA5C336509DB188, OPc = 6F2E82855DEE7C893CB1F7A72FD08B57

❯ ./encode_ki.pl
KI = 8978B79E7C104F678FA5C336509DB188, KIc = FBE8C170F6A5C6C257E5324719674818
```
