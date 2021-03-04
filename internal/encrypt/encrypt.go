package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"

	log "github.com/sirupsen/logrus"
)

// hashTo32Bytes will compute a cryptographically useful hash of the input string.
func hashTo32Bytes(input string) []byte {

	data := sha256.Sum256([]byte(input))
	return data[0:]

}

// Takes two string, plainText and keyString.
// plainText is the text that needs to be encrypted by keyString.
// The function will output the resulting crypto text and an error variable.
func EncryptString(plainText string, keyString string) (cipherTextString string, err error) {
	if keyString == "" {
		log.Fatal("Key to ddecrypt data can't be blank")
	}

	key := hashTo32Bytes(keyString)
	encrypted, err := encryptAES(key, []byte(plainText))
	if err != nil {
		log.Debug(err)
		return "", err
	}

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func EncryptData(data []byte, keyString string) (cipherTextString string, err error) {
	if keyString == "" {
		log.Fatal("Key to ddecrypt data can't be blank")
	}

	key := hashTo32Bytes(keyString)
	encrypted, err := encryptAES(key, data)
	if err != nil {
		log.Debug(err)
		return "", err
	}

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func encryptAES(key, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Debug("Unable to generate cipher")
		return nil, err
	}

	// create two 'windows' in to the output slice.
	output := make([]byte, aes.BlockSize+len(data))
	iv := output[:aes.BlockSize]
	encrypted := output[aes.BlockSize:]

	// populate the IV slice with random data.
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		log.Debug("Unable to populate the IV slice with random data")
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	// note that encrypted is still a window in to the output slice
	stream.XORKeyStream(encrypted, data)
	return output, nil
}

// Takes two strings, cryptoText and keyString.
// cryptoText is the text to be decrypted and the keyString is the key to use for the decryption.
// The function will output the resulting plain text string with an error variable.
func DecryptString(cryptoText string, keyString string) (plainTextString string, err error) {
	if keyString == "" {
		log.Fatal("Key to decrypt data can't be blank")
	}

	encrypted, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		log.Debug("Unable to b64decode string")
		return "", err
	}
	if len(encrypted) < aes.BlockSize {
		log.Debug(fmt.Errorf("cipherText too short. It decodes to %v bytes but the minimum length is 16", len(encrypted)))
		return "", fmt.Errorf("Data can't be decrypted")
	}

	decrypted, err := decryptAES(hashTo32Bytes(keyString), encrypted)
	if err != nil {
		log.Debug("Unable to descrypt string")
		return "", err
	}

	return string(decrypted), nil
}

func DecryptData(cryptoText string, keyString string) (data []byte, err error) {
	if keyString == "" {
		log.Fatal("Key to ddecrypt data can't be blank")
	}

	encrypted, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		log.Debug("Unable to b64decode string")
		return nil, err
	}
	if len(encrypted) < aes.BlockSize {
		log.Debug(fmt.Errorf("cipherText too short. It decodes to %v bytes but the minimum length is 16", len(encrypted)))
		return nil, fmt.Errorf("Data can't be decrypted")
	}

	data, err = decryptAES(hashTo32Bytes(keyString), encrypted)
	if err != nil {
		log.Debug("Unable to descrypt string")
		return nil, err
	}

	return data, nil
}

func decryptAES(key, data []byte) ([]byte, error) {
	// split the input up in to the IV seed and then the actual encrypted data.
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Debug("Unable to generate cipher")
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(data, data)
	return data, nil
}

func EncryptStruct(s interface{}, password string) error {
	log.Debug("Encrypting Data...")

	err := EncryptField(reflect.ValueOf(s), password)
	if err != nil {
		log.Debug("Unable to encrypt Data")
	}

	return err
}

func EncryptField(v reflect.Value, password string) error {
	//log.Debug("Encrypting Field...")
	if v.Kind() != reflect.Ptr {
		log.Trace(v.String(), "Not a pointer value")
		return fmt.Errorf(v.String(), "Not a pointer value")
	}

	v = reflect.Indirect(v)

	switch v.Kind() {

	case reflect.String:
		//log.Debug("Found string")
		if v.IsValid() && v.CanSet() {
			vstring := v.String()
			tmp, err := EncryptString(vstring, password)
			if err != nil {
				log.Trace(v.String(), err)
				//return err
			}
			v.SetString(string(tmp))

		} else {
			log.Trace("String is invalid and can't be set")
		}
	case reflect.Slice:
		//fmt.Println(v)
		//fmt.Println("######MEED TO COME BACK TO THIS encrypt.go reflect.slice")

		for i := 0; i < v.Len(); i++ {
			EncryptField(v.Index(i), password)
		}
	case reflect.Ptr:
		//log.Debug("Found ptr")
		err := EncryptField(v, password)
		if err != nil {
			log.Trace(v.String(), err)
			return err
		}
	case reflect.Struct:
		//log.Debug("Found struct")
		for i := 0; i < v.NumField(); i++ {
			err := EncryptField(v.Field(i).Addr(), password)
			if err != nil {
				log.Trace(v.String(), err)
				//return err
			}

		}
	default:
		//log.Debug("Unsupported kind: ", v.Kind(), "type:", &v)

	}
	//log.Debug("Completed encrypting Field...")
	return nil
}

func DecryptStruct(s interface{}, password string) error {
	log.Debug("Decrypting Data...")

	err := DecryptField(reflect.ValueOf(s), password)
	if err != nil {
		log.Debug("Unable to Decrypt Data")
	}

	return err
}

func DecryptField(v reflect.Value, password string) error {
	//log.Debug("Decrypting Field...")

	//g := reflect.ValueOf(v)

	//fmt.Println(v.Kind())
	if v.Kind() != reflect.Ptr {
		//log.Debug(v.Kind(), "Not a pointer value")
		return fmt.Errorf(v.String(), "Not a pointer value", v.Type().Field(0).Name)
	}

	v = reflect.Indirect(v)

	switch v.Kind() {

	case reflect.String:
		//log.Debug("Found string")
		if v.IsValid() && v.CanSet() {
			vstring := v.String()
			tmp, err := DecryptString(vstring, password)
			if err != nil {
				log.Debug(v.String(), err)
				return err
			}
			v.SetString(string(tmp))

		} else {
			log.Trace("String is invalid and can't be set")
		}
	case reflect.Slice:
		//fmt.Println(v)
		//fmt.Println("######MEED TO COME BACK TO THIS Decrypt.go reflect.slice")

		for i := 0; i < v.Len(); i++ {
			DecryptField(v.Index(i), password)
		}
	case reflect.Ptr:
		//log.Debug("Found ptr")
		err := DecryptField(v, password)
		if err != nil {
			log.Debug(v.String(), err)
			return err
		}
	case reflect.Struct:
		//log.Debug("Found struct")
		for i := 0; i < v.NumField(); i++ {
			err := DecryptField(v.Field(i).Addr(), password)
			if err != nil {
				log.Debug(v.String(), err)
				//return err
			}

		}
	default:
		//log.Debug("Unsupported kind: ", v.Kind(), "type:", &v)

	}
	//log.Debug("Completed Decrypting Field...")
	return nil
}
