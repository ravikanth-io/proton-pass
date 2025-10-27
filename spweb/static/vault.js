// webapp/static/vault.js
// Very small client-side encrypted vault manager
// Vault format (binary):
// [16 bytes salt][12 bytes nonce][ciphertext bytes]
// ciphertext = AES-GCM encrypt(JSON.stringify({entries:[{name,username,password,notes}] }))

const VaultClient = (function(){
  let masterKey = null;
  let vaultCache = null; // decrypted object
  let salt = null;
  let storageKey = 'smartpass_vault_bin';

  async function deriveKey(password, saltBytes) {
    const enc = new TextEncoder();
    const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 200000,
      hash: 'SHA-256'
    }, pwKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
    return key;
  }

  function concatBuffers(a,b){ // Uint8Array
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  async function initOrOpen(password) {
    // if no vault stored, create empty and store encrypted form
    const stored = localStorage.getItem(storageKey);
    if (!stored) {
      // create random salt and empty vault
      salt = crypto.getRandomValues(new Uint8Array(16));
      masterKey = await deriveKey(password, salt);
      vaultCache = { entries: [] };
      await persistVault();
      return true;
    }
    // open existing
    const bin = base64ToUint8(atob(stored));
    const s = bin.slice(0,16);
    const nonce = bin.slice(16,28);
    const ct = bin.slice(28);
    salt = s;
    try {
      masterKey = await deriveKey(password, s);
      const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv: nonce}, masterKey, ct);
      const dec = new TextDecoder();
      vaultCache = JSON.parse(dec.decode(pt));
      return true;
    } catch (e) {
      console.warn('Failed to open vault:', e);
      masterKey = null;
      vaultCache = null;
      return false;
    }
  }

  async function persistVault(){
    if (!masterKey || !vaultCache) return false;
    const enc = new TextEncoder();
    const pt = enc.encode(JSON.stringify(vaultCache));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv: nonce}, masterKey, pt);
    const out = concatBuffers(concatBuffers(salt, nonce), new Uint8Array(ct));
    const b64 = btoa(uint8ToString(out));
    localStorage.setItem(storageKey, b64);
    return true;
  }

  async function add(entry) {
    if (!vaultCache) return false;
    vaultCache.entries.push(entry);
    return await persistVault();
  }
  async function list() {
    if (!vaultCache) return [];
    return vaultCache.entries;
  }
  async function getPassword(index) {
    if (!vaultCache) return null;
    return vaultCache.entries[index].password;
  }
  async function remove(index) {
    if (!vaultCache) return false;
    vaultCache.entries.splice(index,1);
    return await persistVault();
  }
  async function exportEncrypted() {
    const stored = localStorage.getItem(storageKey);
    if (!stored) return null;
    const bin = atob(stored);
    // return blob
    const u8 = base64ToUint8(bin);
    return new Blob([u8], {type:'application/octet-stream'});
  }
  async function importEncrypted(u8arr) {
    // u8arr = Uint8Array
    const b64 = btoa(uint8ToString(u8arr));
    localStorage.setItem(storageKey, b64);
    return true;
  }

  // helpers
  function uint8ToString(u8) {
    let s = '';
    for (let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
    return s;
  }
  function base64ToUint8(b64str){
    const str = b64str;
    const u = new Uint8Array(str.length);
    for (let i=0;i<str.length;i++) u[i] = str.charCodeAt(i);
    return u;
  }

  return { initOrOpen, add, list, getPassword, remove, exportEncrypted, importEncrypted };
})();
