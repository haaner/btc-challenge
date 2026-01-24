
# Summary

The code within this project allows to fiddle with Bitcoin addresses, public/private key pairs, transactions and handle some elliptic curve stuff.

It has been created in order to recover private keys from Bitcoin addresses with outgoing transactions.

# Usage

### Activate Python
```
source .venv/bin/activate
```

### Install the required Python libraries
```
pip install -r requirements.txt
```

### Fetch the rsz-data of all outgoing transactions for an UTXO 
```
./rsz.py 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8 > 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8.rsz
```

### Create opt-data from a rsz
```
./rsz2opt.py < 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8.rsz > 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8.opt
./rsz2opt.py --nonce-bits-equal=64 --nonce-bits-max=128 < 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8.rsz > 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8_nbe64_nbm128.opt
```

### Download a copy of 0ptX

https://www.0ptx.de/download

**Important**: Make sure to download a version >= 2.4.2 - older versions do not support searching for solutions with modulo restrictions.

### Run 0ptX against the opt-data
```
./0ptX 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8.opt
```

In case 0ptX finds solutions you first have to decrypt the generated csol-file in order to get a sol file, which is needed for the final step - see here for details on decryption: https://www.0ptx.de/lizenz

### Check the private keys in a (0ptX-generated) sol file against an utxo
```
./sol_check.py 18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8.sol
```

# Shortcomings

This code can only deal with transactions using the original [ECDSA](https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/ecdsa/) signature scheme. [Schnoor signatures](https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/schnorr/), which have been introduced with the Taproot upgrade are not covered yet.

# Acknowledgements

This project and its implementation was heavily inspired by the following articles and website(s):

https://medium.com/@ottosch/manually-creating-and-signing-a-bitcoin-transaction-87fbbfe46032
https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526a
https://learnmeabitcoin.com/
