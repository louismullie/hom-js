var Paillier = (function () {
  
  /* Utility functions for working with Paillier */
  var Utils = {
    
    /* Generate a random big number */
    random: function (bitLength) {
      
      var wordLength = bitLength / 4 / 8;
      
      var randomWords = sjcl.random.randomWords(wordLength),
          randomHex = sjcl.codec.hex.fromBits(randomWords);

      return new BigInteger(randomHex, 16);
      
    }
    
  };
  
  /* Public interface to the Paillier cryptosystem */
  var Paillier = {
    
    generateKeys: function(keySize) {
      
      var p, q, n;

      /* 
       * Choose two large prime numbers p and q
       * randomly and independently of each other
       * such that gcd(pq, (p - 1)(q - 1)) = 1.
       */
      while(true) {
        
        // Generate a random prime p
        do {
          p = Utils.random(keySize>>1);
        } while (!p.isProbablePrime(10));

        // Generate a random prime q
        do {
          q = Utils.random(keySize>>1);
        } while(!q.isProbablePrime(10));

        // Generate n = p * q
        n = p.multiply(q);
        
        // Break when condition satisfied
        if (!(n.testBit(keySize - 1)) ||
           (p.compareTo(q) == 0)) break;
      }
      
      // Calculate p - 1 and q - 1
      var p1 = p.subtract(BigInteger.ONE),
          q1 = q.subtract(BigInteger.ONE);
      
      /* Calculate lambda = lcm(p - 1, q - 1), using
       * Carmichael's function, and substituting
       * lcm(a,b) for a.multiply(b).divide(a.gcd(b)) */
      var l = p1.multiply(q1).divide(p1.gcd(q1));
      
      // Create a keypair with parameters.
      return new this.Keypair(keySize, n, l);
      
    },
    
    /*
     * Represents a keypair in the Paillier cryptosystem.
     */
    Keypair: function (keySize, n, l) {
    
      this.pub = new Paillier.PublicKey(keySize, n);
      
      if (l) this.sec = new Paillier.PrivateKey(l, this.pub);
      
    },
    
    /*
     * Represents a public key (n, g) in the Paillier cryptosystem.
     */
    PublicKey: function(keySize, n) {
      
      if (keySize % 2 != 0)
        throw 'Keysize should be even.'

      this.keySize = keySize; this.n = n;
      
      // Calculate n^2
      this.n2 = n.square();
      
      // Calculate n + 1
      this.np1 = n.add(BigInteger.ONE);
      
      // Initialize r^n cache
      this.rnCache = [];
      
    },
    
    /* 
     * Represents a private key (lambda, mu) in the Paillier cryptosystem.
     */
    PrivateKey: function(lambda, pubKey) {
      
      this.lambda = lambda;
      this.pubKey = pubKey;
      
      // calculate u = g^lambda mod n^2
      var u = pubKey.np1.modPow(this.lambda,pubKey.n2);
      
      // calculate mu = L(u)^-1 mod n
      this.mu = this.pubKey.L(u).modInverse(pubKey.n);
      
      // ensure existence of the mod inverse
      if (this.mu.toString() == '0')
        throw 'Error: n does not divide order of g';
      
    }
    
  };

  Paillier.PublicKey.prototype = {
    
    /*
     * Encrypt a plaintext message m
     */
    encrypt: function(m) {
    
      // Ensure the input message is a BigInteger.
      var m = this.convertToBn(m);
      
      return this.randomize(this.n.multiply(m)
             .add(BigInteger.ONE).mod(this.n2));
      
    },
    
    /* Add two encrypted ciphertexts */
    add: function(a,b) {
      
      return a.multiply(b).remainder(this.n2);
      
    },
    
    /* Multiply two encrypted ciphertexts */
    mult: function(a,b) {
      
      return a.modPow(this.convertToBn(b), this.n2);
      
    },
    
    /* Perform the L function L(x) = (x - 1) /n */
    L: function (x) {
      
      return x.subtract(BigInteger.ONE).divide(this.n);
      
    },
    
    randomize: function(a) {
      
      // First find a suitable r^n to use.
      var rn;

      // Either we have pre-computed values.
      if (this.rnCache.length > 0) {
        rn = this.rnCache.pop();
      // Or we need to generate a new one.
      } else {
        rn = this.generateRn();
      }

      return (a.multiply(rn)).mod(this.n2);
      
    },
    
    /*
     * Precompute values for r^n by calling
     * the generateRn procedure n times.
     */
    precompute: function(n) {
      
      for (var i = 0; i < n; i++) {
        this.rnCache.push(this.generateRn());
      }
      
    },
    
    /*
     * Generate a random r^n value by first
     * generating a random r in Z*{n}, and
     * then calculating r^n mod n^2.
     */
    generateRn: function() {
      
      do {
        r = Utils.random(this.keySize);
      } while(r.compareTo(this.n) >= 0);
      
      return r.modPow(this.n, this.n2);
      
    },
    
    /* 
     * Convert a number or string to a BigInteger
     */
    convertToBn: function (m) {
      
      if (typeof(m) == 'string'){
        m = new BigInteger(m);
      } else if (m.constructor != BigInteger) {
        m = new BigInteger(parseInt(m).toString());
      }
      
      return m;
      
    }
    
  };
  
  Paillier.PrivateKey.prototype = {
    
    /*
     * Given a ciphertext c to decrypt, calculate
     * plaintext m = L(c^λ mod n^2) * µ * mod n
     */
    decrypt: function(c) {
      
      var x = this.pubKey.L(
        c.modPow(this.lambda,this.pubKey.n2));
       
      var m = x.multiply(this.mu).mod(this.pubKey.n);
      
      return m;
      
    }
    
  };
  
  return Paillier;
  
})();
