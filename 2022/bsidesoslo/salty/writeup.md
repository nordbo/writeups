# salty

Bug:
We have a use after free / double free as we can free the flag without the flag pointer being deleted.

We can use this bug to have both a note's ciphertext and the flag pointing to the same memory region on the heap. When we then print what is supposed to be the note's ciphertext, we leak the flag's key and nonce so that we can decrypt the flag.

summary:
* create a note
* print the flag (first time you do this a new heap chunk of 0x70 bytes is calloced)
* free the flag 
* edit the note, and change the size to 73. This will take the chunk that was used for the flag, and allocate it to the note. Now both the note0->ciphertext and the flag points to the same chunk. The last byte of the ciphertext will overwrite the least significant byte of the flags ciphertext pointer, so when we run the flag function again this byte needs to be 0. Hence the 1 byte bruteforce in the solve script.
* Run the print flag function again. Since the flag pointer is already to pointing to an address, we will not calloc a new chunk, but overwrite the note0->ciphertext with the flag key and nonce. 

* Print note 0 (which now contains the flag seed, key and nonce)
* Decrypt flag

flag: flag{i_guess_calling_it_crypto_is_a_bit_of_a_stretch}
