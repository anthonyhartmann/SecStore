package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"
	"strings"
	"errors"
)

var keyLen = 32
var argonKeyLen = uint32(32)	// 256/8 = 32
var rsaEncLen = userlib.RSAKeySize / 8
var rsaSignLen = 36
var hmacLen = userlib.HashSize	// 32
var ivLen = userlib.BlockSize


// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func CFBEncrypt(iv []byte, key []byte, msg []byte) []byte {
	encTool := userlib.CFBEncrypter(key, iv)
	var encMsg = make([]byte, len(msg))
	encTool.XORKeyStream(encMsg, msg)
	return encMsg
}

func CFBDecrypt(iv []byte, key []byte, encMsg []byte) []byte {
	decTool := userlib.CFBDecrypter(key, iv)
	var marshalMsg = make([]byte, len(encMsg))
	decTool.XORKeyStream(marshalMsg, encMsg)
	return marshalMsg
}

func CheckHMAC(value []byte, key []byte) (finalValue []byte, err error) {
	encIV := value[:len(value) - hmacLen]
	hmacVal := value[len(value) - hmacLen:]
	hmac := userlib.NewHMAC(key)
	hmac.Write([]byte(encIV))
	hmacVal2 := hmac.Sum([]byte(""))
	if !userlib.Equal(hmacVal, hmacVal2) {
		return nil, errors.New("User data has been corrupted.")
	}

	return encIV, nil
}

func SignHMAC(value []byte, key []byte) (finalValue []byte) {
	hmac := userlib.NewHMAC(key)
	hmac.Write([]byte(value))
	hmacVal := hmac.Sum([]byte(""))
	finalValue = append(value, hmacVal...)
	return finalValue
}

// The structure definition for a user record
type User struct {
	Username string
	FileMap map[string][][]byte
	Iv []byte
	ArgonLoc []byte
	ArgonSK []byte
	ArgonHMAC []byte
	AprivKd *userlib.PrivateKey
	AprivKs *userlib.PrivateKey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
	Filename string
	K2e []byte
	K2s []byte
	R2 []byte
	AppendArray []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	// initialize and fill user struct
	var userdata User
	userdata.Username = username
	userdata.FileMap = make(map[string][][]byte)
	userdata.AprivKd, err = userlib.GenerateRSAKey()
	userdata.AprivKs, err = userlib.GenerateRSAKey()

	// RSA keys for sharing file's info
	ApubKe := userdata.AprivKd.PublicKey
	ApubKs := userdata.AprivKs.PublicKey
	userlib.KeystoreSet(username + "encrypt", ApubKe)
	userlib.KeystoreSet(username + "sign", ApubKs)

	// byte of common strings
	bUsername := []byte(username)
	bPassword := []byte(password)
	bEmpty := []byte("")
	iv := userlib.RandomBytes(ivLen)

	// generate argon keys for locating and decrypting user struct
	hash := userlib.NewSHA256()
	hash.Write(bPassword)
	hmacPass := userlib.NewHMAC(bPassword)
	hmacPass.Write(bUsername)

	argonLoc := userlib.Argon2Key(bPassword, bUsername, argonKeyLen)
	argonSK := userlib.Argon2Key(hmacPass.Sum(bEmpty), bUsername, argonKeyLen)
	argonHMAC := userlib.Argon2Key(hash.Sum(bEmpty), bUsername, argonKeyLen)
	userdata.ArgonLoc = argonLoc
	userdata.ArgonSK = argonSK
	userdata.ArgonHMAC = argonHMAC
	userdata.Iv = iv

	// marshal user struct
	marshalUser, _ := json.Marshal(userdata)

	// encrypt the marshal
	encUserdata := CFBEncrypt(iv, argonSK, marshalUser)

	// concat everything together and HMAC
	encIVUser := append(iv, encUserdata...)
	value := SignHMAC(encIVUser, argonHMAC)

	// store userstruct encryption in datastore
	strArgonLoc := string(argonLoc)
	userlib.DatastoreSet(strArgonLoc, value)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// byte of strings
	bUsername := []byte(username)
	bPassword := []byte(password)
	bEmpty := []byte("")

	// generate argon keys for locating and decrypting user struct
	hash := userlib.NewSHA256()
	hash.Write(bPassword)
	hmacPass := userlib.NewHMAC(bPassword)
	hmacPass.Write(bUsername)

	argonLoc := userlib.Argon2Key(bPassword, bUsername, argonKeyLen)
	argonSK := userlib.Argon2Key(hmacPass.Sum(bEmpty), bUsername, argonKeyLen)
	argonHMAC := userlib.Argon2Key(hash.Sum(bEmpty), bUsername, argonKeyLen)

	// check whether username or password is correct
	strArgonLoc := string(argonLoc)
	value, ok := userlib.DatastoreGet(strArgonLoc)
	if !ok {
		return nil, errors.New("Username or password is invalid.")
	}

	// check whether data has been corrupted
	encIVUser, err:= CheckHMAC(value, argonHMAC)
	if err != nil {
		return nil, err
	}

	// decrypt the data
	iv := value[:ivLen]
	encUserdata := encIVUser[ivLen:]
	marshalUserdata := CFBDecrypt(iv, argonSK, encUserdata)

	// unmarshal the data
	var userdata User
	_ = json.Unmarshal(marshalUserdata, &userdata)

	return &userdata, err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	r1 := userlib.RandomBytes(keyLen)
	k1e := userlib.RandomBytes(keyLen)
	k1s := userlib.RandomBytes(keyLen)
	
	r2 := userlib.RandomBytes(keyLen)
	k2e := userlib.RandomBytes(keyLen)
	k2s := userlib.RandomBytes(keyLen)

	//marshalling the file
	marshalFile, _ := json.Marshal(data)

	//encrypting the marshalled json data
	iv := userlib.RandomBytes(ivLen)
	encFile := CFBEncrypt(iv, k2e, marshalFile)

	// concat everything together and HMAC
	encIVFile := append(iv, encFile...)
	value := SignHMAC(encIVFile, k2s)

	userlib.DatastoreSet(string(r2), value)

	var fileStruct File
	fileStruct.Filename = filename
	fileStruct.K2e = k2e
	fileStruct.K2s = k2s
	fileStruct.R2 = r2
	fileStruct.AppendArray = make([]byte, 0)

	//marshal the file struct
	marshalStruct, _ := json.Marshal(fileStruct)

	//encrypting the marshalled json file struct
	iv2 := userlib.RandomBytes(ivLen)
	encStruct := CFBEncrypt(iv2, k1e, marshalStruct)

	// concat file struct encryption together again and HMAC again
	encIVStruct := append(iv2, encStruct...)
	final := SignHMAC(encIVStruct, k1s)

	//upload file struct to datastore
	userlib.DatastoreSet(string(r1), final)

	//updating the user's file mappings  
	var fileInfo = make([][]byte, 3)
	fileInfo[0] = r1
	fileInfo[1] = k1e
	fileInfo[2] = k1s
	userdata.FileMap[filename] = fileInfo

	//------ reupload user struct to datastore -------
	argonLoc := userdata.ArgonLoc
	argonSK := userdata.ArgonSK
	argonHMAC := userdata.ArgonHMAC
	ivUser := userdata.Iv

	// marshal user struct
	marshalUser, _ := json.Marshal(userdata)

	// encrypt the marshal
	encUserdata := CFBEncrypt(ivUser, argonSK, marshalUser)

	// concat everything together and HMAC
	encIVUser := append(ivUser, encUserdata...)
	valueUser := SignHMAC(encIVUser, argonHMAC)

	// store userstruct encryption in datastore
	strArgonLoc := string(argonLoc)
	userlib.DatastoreSet(strArgonLoc, valueUser)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	fileInfo := userdata.FileMap[filename]
	r1 := fileInfo[0]
	k1e := fileInfo[1]
	k1s := fileInfo[2]
	fstruct, ok := userlib.DatastoreGet(string(r1))
	if !ok {
		return errors.New("File not found.")
	}
	
	encIVStruct, err := CheckHMAC(fstruct, k1s)

	if err != nil {
		return errors.New("File has been corrupted.")
	}

	//decrypt the file struct
	iv := encIVStruct[:ivLen]
	encStruct := encIVStruct[ivLen:]
	marshalStruct := CFBDecrypt(iv, k1e, encStruct)

	// unmarshal the file struct
	var fileStruct File
	err = json.Unmarshal(marshalStruct, &fileStruct)
	
	//append to the plaintext append array
	fileStruct.AppendArray = append(fileStruct.AppendArray, data...)

	//re marshall the file struct
	newMarshalStruct, _ := json.Marshal(fileStruct)
	
	//re encrypt the marshalled file struct
	newIv := userlib.RandomBytes(ivLen)
	newEncStruct := CFBEncrypt(newIv, k1e, newMarshalStruct)

	newEncIVFile := append(newIv, newEncStruct...)
	trueFileStruct := SignHMAC(newEncIVFile, k1s)

	userlib.DatastoreSet(string(r1), trueFileStruct)
	return err	
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	fileInfo := userdata.FileMap[filename]
	if (fileInfo == nil){
		return nil, errors.New("fuck")
	}
	r1 := fileInfo[0]
	k1e := fileInfo[1]
	k1s := fileInfo[2]

	fstruct, ok := userlib.DatastoreGet(string(r1))
	if !ok {
		return nil, nil
	}
	
	// check HMAC filestruct data
	encIVStruct, err := CheckHMAC(fstruct, k1s)

	if err != nil {
		return nil, errors.New("File struct has been tampered with in LoadFile")
	}

	// decrypt the file struct
	iv := encIVStruct[:ivLen]
	encStruct := encIVStruct[ivLen:]
	marshalStruct := CFBDecrypt(iv, k1e, encStruct)

	// unmarshal the file struct
	var fileStruct File
	err = json.Unmarshal(marshalStruct, &fileStruct)

	//assign all the important filestruct data
	k2e := fileStruct.K2e
	k2s := fileStruct.K2s
	r2 := fileStruct.R2
	appendArray := fileStruct.AppendArray

	// retrieve the file data
	filedata, ok := userlib.DatastoreGet(string(r2))
	if !ok {
		return nil, errors.New("File not found in datastore.")
	}

	// check HMAC for the file data
	encIVFile, err := CheckHMAC(filedata, k2s)

	if err != nil {
		return nil, errors.New("File has been tampered with.")
	}

	//decrypt the file data
	iv2 := encIVFile[:ivLen]
	encFile := encIVFile[ivLen:]
	marshalFile := CFBDecrypt(iv2, k2e, encFile)

	// unmarshal the file data
	var trueFile []byte
	err = json.Unmarshal(marshalFile, &trueFile)

	//append all unappended data to the file
	retData := append(trueFile , appendArray...)

	//marshalling the file
	marshalFile2, err := json.Marshal(retData)

	//encrypting the marshalled json data
	iv3 := userlib.RandomBytes(ivLen)
	encFile2 := CFBEncrypt(iv3, k2e, marshalFile2)

	// concat file data together and HMAC
	encIVFile2 := append(iv3, encFile2...)
	filedata2 := SignHMAC(encIVFile2, k2s)

	userlib.DatastoreSet(string(r2), filedata2)

	//reset the appendarray to the empty array
	fileStruct.AppendArray = make([]byte, 0)

	//re marshall the file struct
	newMarshalStruct, err := json.Marshal(fileStruct)
	
	//re encrypt the marshalled file struct
	newIv := userlib.RandomBytes(ivLen)
	newEncStruct := CFBEncrypt(newIv, k1e, newMarshalStruct)

	newEncIVFile := append(newIv, newEncStruct...)
	trueFileStruct := SignHMAC(newEncIVFile, k1s)

	userlib.DatastoreSet(string(r1), trueFileStruct)

	return retData, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	fileInfo, found := userdata.FileMap[filename]
	if !found {
		return "", nil
	}
	r1 := fileInfo[0]
	k1d := fileInfo[1]
	k1s := fileInfo[2]
	msg := append(r1, append(k1d, k1s...)...)

	recApubKe, _ := userlib.KeystoreGet(recipient + "encrypt")

	tag := userlib.RandomBytes(keyLen)

	encMsg, err := userlib.RSAEncrypt(&recApubKe, msg, tag)
	encTagMsg := append(tag, encMsg...)
	signTagMsg, err := userlib.RSASign(userdata.AprivKs, encTagMsg)
	value := append(encTagMsg, signTagMsg...)

	return string(value), err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	senApubKs, _ := userlib.KeystoreGet(sender + "sign")

	msg := []byte(msgid)

	// split msg into its respective parts
	signTagMsg := msg[len(msg) - rsaEncLen:]
	encTagMsg := msg[:len(msg) - rsaEncLen]
	encMsg := encTagMsg[keyLen:len(encTagMsg)]
	tag := encTagMsg[:keyLen]

	// check whether the data is from sender and not malicious
	err := userlib.RSAVerify(&senApubKs, encTagMsg, signTagMsg)
	if err != nil {
		return errors.New("File has been corrupted")
	}

	// decrypt the message
	value, err := userlib.RSADecrypt(userdata.AprivKd, encMsg, tag)
	if err != nil {
		return errors.New("File can not be decrypted")
	}

	// split info from 
	var fileInfo = make([][]byte, 3)
	fileInfo[0] = value[:keyLen]			// r1
	fileInfo[1] = value[keyLen:keyLen*2]	// k1d
	fileInfo[2] = value[keyLen*2:]			// k1s

	userdata.FileMap[filename] = fileInfo

	//------ reupload user struct to datastore -------
	argonLoc := userdata.ArgonLoc
	argonSK := userdata.ArgonSK
	argonHMAC := userdata.ArgonHMAC
	ivUser := userdata.Iv

	// marshal user struct
	marshalUser, _ := json.Marshal(userdata)

	// encrypt the marshal
	encUserdata := CFBEncrypt(ivUser, argonSK, marshalUser)

	// concat everything together and HMAC
	encIVUser := append(ivUser, encUserdata...)
	valueUser := SignHMAC(encIVUser, argonHMAC)

	// store userstruct encryption in datastore
	strArgonLoc := string(argonLoc)
	userlib.DatastoreSet(strArgonLoc, valueUser)


	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// load file info from user's FileMap
	fileInfo := userdata.FileMap[filename]
	r1 := fileInfo[0]

	// load data from filename
	data, err := userdata.LoadFile(filename)

	// delete it from anywhere that's important
	userlib.DatastoreDelete(string(r1))
	delete(userdata.FileMap, filename)

	// restore the file at a new location with new encryption/sign keys
	userdata.StoreFile(filename, data)

	return err
}