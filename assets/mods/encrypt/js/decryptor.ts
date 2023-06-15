import snackbar from 'mods/snackbar/js/index.ts';
import params from '@params';

class Decryptor {
  /**
   * Encodes a utf8 string as a byte array.
   * @param {string} str
   * @returns {Uint8Array}
   */
  private str2buf (str: string): Uint8Array {
    return new TextEncoder().encode(str)
  }

  /**
   * Decodes a byte array as a utf8 string.
   * @param {Uint8Array} buffer
   * @returns {string}
   */
  private buf2str (buffer: Uint8Array): string {
    return new TextDecoder('utf-8').decode(buffer)
  }

  /**
   * Decodes a string of hex to a byte array.
   * @param {string} hexStr
   * @returns {Uint8Array}
   */
  private hex2buf (hexStr: string): Uint8Array {
    return new Uint8Array(hexStr.match(/.{2}/g).map((h) => parseInt(h, 16)))
  }

  /**
   * Given a passphrase, this generates a crypto key
   * using `PBKDF2` with SHA256 and 1000 iterations.
   * If no salt is given, a new one is generated.
   * The return value is an array of `[key, salt]`.
   * @param {string} passphrase
   * @param {UInt8Array} salt [salt=random bytes]
   * @returns {Promise<[CryptoKey,UInt8Array]>}
   */
  private async deriveKey (
    passphrase: string,
    salt: Uint8Array
  ): Promise<[CryptoKey, Uint8Array]> {
    salt = salt ?? crypto.getRandomValues(new Uint8Array(8))
    return await crypto.subtle
      .importKey('raw', this.str2buf(passphrase), 'PBKDF2', false, [
        'deriveKey',
      ])
      .then(
        async (key) =>
          await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' },
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
          )
      )
      .then((key) => [key, salt])
  }

  decryptBlock (block: HTMLElement, password = ''): void {
    if (password === '') {
      const passwordEl = block.querySelector('input') as HTMLInputElement
      password = passwordEl.value
    }
    if (password === '') {
      return
    }
    const content = block.querySelector('.hugo-encrypt-content') as HTMLElement
    this.decrypt(password, content.innerText)
      .then((plaintext) => {
        /**
         * calculate sha1 of decrypted text and check if it
         * matches the sha1 at the bottom of the decrypted text
         * to get the same hash that was added during encryption we
         * need to remove the last line
         */
        this.digestMessage(plaintext.replace(/\r?\n?[^\r\n]*$/, ''))
          .then((sum) => {
            if (plaintext.includes(sum)) {
              content.innerHTML = plaintext
              block.classList.add('decrypted')
              this.rememberPassword(
                block.getAttribute('data-id') ?? '',
                password
              )
            }
          })
          .catch((err) => {
            throw err
          })
      })
      .catch((err) => {
        snackbar.add(block.getAttribute('data-error-msg'))
        // clear password if exists.
        this.clearPassword(block.getAttribute('data-id') ?? '')
        console.log(err)
      })
  }

  private storage (): Storage {
    return params.storage === 'session' ? sessionStorage : localStorage
  }

  private cacheKey (id: string): string {
    console.log(location.pathname, window.location.pathname)
    return `hugo-encrypt-password-${location.pathname}-${id}`
  }

  private rememberPassword (id: string, password: string): void {
    this.storage().setItem(this.cacheKey(id), password)
  }

  private clearPassword (id: string): void {
    this.storage().removeItem(this.cacheKey(id))
  }

  recover (block: HTMLElement): void {
    const id = block.getAttribute('data-id')
    if (id === null || id === undefined) {
      return
    }
    const pwd = this.storage().getItem(this.cacheKey(id))
    if (pwd !== null) {
      this.decryptBlock(block, pwd)
    }
  }

  /**
   * Given a key and ciphertext (in the form of a string) as given by `encrypt`,
   * this decrypts the ciphertext and returns the original plaintext
   * @param {string} passphrase
   * @param {string} saltIvCipherHex
   * @returns {Promise<string>}
   */
  private async decrypt (
    passphrase: string,
    saltIvCipherHex: string
  ): Promise<string> {
    const [salt, iv, data] = saltIvCipherHex.split('-').map(this.hex2buf)
    return await this.deriveKey(passphrase, salt)
      .then(
        async ([key]) =>
          await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data)
      )
      .then((v) => this.buf2str(new Uint8Array(v)))
  }

  /**
   * @name: digestMessage
   * @description: hashing string
   * @param {string} message
   * @returns {Promise<string>}
   */
  private async digestMessage (message: string): Promise<string> {
    const msgUint8 = new TextEncoder().encode(message)
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgUint8)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    return hashHex
  }
}

export default Decryptor
