describe("Paillier", function () {
  
  var keys;
  
  var valA = 2, valB = 3, valC = 4;
  
  it ("should generate keys", function () {
    
    keys = Paillier.generateKeys(1024);
    
  });
  
  it ("should precompute", function () {
    
    keys.pub.precompute(4);
    
  });
  
  it ("should encrypt big ints", function (){
    
    encA = keys.pub.encrypt(valA);
    encB = keys.pub.encrypt(valB);
    
  });
  
  it ("should add", function () {
    
    encAB = keys.pub.add(encA, encB);
    
  });
  
  it ("should multiply", function () {
    
    encABC = keys.pub.mult(encAB, valC);
    
  });
  
  it ("should decrypt", function () {
    
    plaintext = keys.sec.decrypt(encABC);
    
    expect(plaintext.intValue()).toEqual(20);
    
  });
  
  
});