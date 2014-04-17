##pailler-js

A Javascript implementation of the [Paillier cryptosystem](http://en.wikipedia.org/wiki/Paillier_cryptosystem#Semantic_Security), invented by Pascal Pailler in 1999. The Paillier cryptosystem is an additive homomorphic system, meaning that given only the public-key and the encryption of `m1` and `m2`, one can compute the encryption of `m1 + m2`.

###Usage

**Addition**
  
```javascript
var keys = Paillier.generateKeys(1024);

var encA = keys.pub.encrypt(7891),
    encB = keys.pub.encrypt(3456);

var encSum = keys.pub.add(encA, encB),
    decSum = keys.sec.decrypt(encSum);

// decSum is equal to 11347
```

**Multiplication**

```javascript
var keys = Paillier.generateKeys(1024);

var encA = keys.pub.encrypt(7891);

var encMul = keys.pub.mult(encA, 3456),
    decMul = keys.sec.decrypt(encMul);

// decMul is equal to 27271296
```

###Dependencies

Depends on `sjcl.js` and `jsbn.js` (included in this repository under the `lib/` folder).

###License

This code is licensed under the GPL v3.