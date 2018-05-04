/**
 * AES with PBKDF2
 *
 * An implementation of Password-Based Key Derivation Function 2 (PBKDF2) with Advanced Encryption System (AES).
 *
 * Copyright (c) 2018. Aryo Karbhawono. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the copyright holder.
 * 4. Neither the name of the copyright holder nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package aespbkdf2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

// Example Usage
// func main() {
// 	c := Encrypt("this is password", "testing data")
// 	fmt.Println(c)
// 	fmt.Println(Decrypt("this is password", c))
// }

/**
 * Key Derivation
 * @param  {[type]} passphrase string        [The Passphrase]
 * @param  {[type]} salt       []byte       ([]byte,      []byte [Sequence of bits/random data]
 * @return {[type]}            [derivationKey]
 */
func derivationKey(passphrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New), salt
}

/**
 * Encrypt Message
 * @param {[type]} passphrase       string  [The Passphrase]
 * @param {[type]} plaintext        string  [The PlainText]
 * @return {[type]} Encrypt			string  [returning object]
 */
func Encrypt(passphrase, plaintext string) string {

	key, salt := derivationKey(passphrase, nil)

	iv := make([]byte, 12)
	rand.Read(iv)

	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data := aesgcm.Seal(nil, iv, []byte(plaintext), nil)

	var buffer bytes.Buffer
	_salt := hex.EncodeToString(salt)
	_iv := hex.EncodeToString(iv)
	_data := hex.EncodeToString(data)

	buffer.WriteString(_salt)
	buffer.WriteString("-")
	buffer.WriteString(_iv)
	buffer.WriteString("-")
	buffer.WriteString(_data)

	return buffer.String()
}

/**
 * Decrypt Message
 * @param {[type]} passphrase       string  [The Passphrase]
 * @param {[type]} ciphertext       string  [The ChiperText]
 * @return {[type]} Dencrypt		string  [returning object]
 */
func Decrypt(passphrase, ciphertext string) string {

	arr := strings.Split(ciphertext, "-")

	salt, _ := hex.DecodeString(arr[0])
	iv, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])

	key, _ := derivationKey(passphrase, salt)

	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data, _ = aesgcm.Open(nil, iv, data, nil)

	return string(data)
}
