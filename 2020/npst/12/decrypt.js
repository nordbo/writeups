//node decrypt.js

const crypto = require("crypto");

function getSecretPasswordNumber(n) {
    return Math.PI.toFixed(48).toString().split(".")[1].slice(n, n+2);
  }

function getPassword(date) {
    const passwords = {
      "06.12.19": "passord-" + getSecretPasswordNumber(3),
      "07.12.19": "passord-" + getSecretPasswordNumber(5),
      "08.12.19": "passord-" + getSecretPasswordNumber(8),
      "09.12.19": "passord-" + getSecretPasswordNumber(13),
      "10.12.19": "passord-" + getSecretPasswordNumber(21),
      "11.12.19": "passord-" + getSecretPasswordNumber(34)
    };
    // 06.12.19: vi har ikke flere passord etter 10. Burde vurdere alternative
    // løsninger.
    return passwords[date] || `fant ikke passord for ${date}`;
  }
  function getFlag() {
    // Det er sikkert smartere å kryptere flagget først, og bare skrive inn det
    // krypterte resultatet her, enn å kryptere på serveren hver gang.
    // 11.12.19: Kryptert flagget nå. Vi kan sikkert slette encrypt-funksjonen?
    return "e5a8aadb885cd0db6c98140745daa3acf2d06edc17b08f1aff6daaca93017db9dc8d7ce7579214a92ca103129d0efcdd";
  }
  function formatSalt(salt) {
    return salt.toLowerCase();
  }

function decrypt(password, salt, input) {
    const algorithm = "aes-192-cbc";
    
    const key = crypto.scryptSync(password, formatSalt(salt), 24);
    
    const iv = Buffer.alloc(16, 0);
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    
    let decrypted = decipher.update(input, 'hex','utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  pw = getPassword('11.12.19')
  res = decrypt(pw, 'NaHSO4', getFlag())

  console.log(res)