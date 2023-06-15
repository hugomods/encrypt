import Decryptor from './decryptor'

(() => {
  document.addEventListener('DOMContentLoaded', () => {
    const decryptor = new Decryptor()
    const buttons = document.querySelectorAll<HTMLButtonElement>('.hugo-decrypt-button')
    buttons.forEach(btn => {
      const block = btn.closest('.hugo-encrypt') as HTMLElement
      decryptor.recover(block)
      btn.addEventListener('click', () => {
        decryptor.decryptBlock(block)
      })
    })
  })
})()
