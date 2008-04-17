#
class NSSError(Exception):
	pass

class NSSBadPassword(NSSError):
	pass

cdef extern from "./nss.h":
	ctypedef struct SECItem:
		int		type
		char*	data
		unsigned int	len


	int pwdcallcount
	void fixup_password()
	void set_password(char*)
	extern void SEC_Init()
	extern int NSS_Init(char *configdir)
	extern int NSS_Shutdown()
	extern void free(void*)
	int PK11SDR_Encrypt(SECItem *keyid, SECItem *data, SECItem *result, void *cx)
	int PK11SDR_Decrypt(SECItem *data, SECItem *result, void *cx)

cdef extern from "Python.h":
	object PyString_FromStringAndSize(char *, int)
	char* PyString_AsString(object)
	
def decrypt_pass(char *path, char* password, object encrypted_string):
	cdef int ok
	
	set_password(password)
	ok = NSS_Init( path )

	if not ok == 0:
		raise NSSError("NSS_Init failed.")

	fixup_password()

	cdef  SECItem input
	cdef  SECItem output

	input.data = PyString_AsString(encrypted_string)
	input.len = len(encrypted_string)
	input.type = 0

	output.type = 0
	output.len = 0 
	output.data = NULL

	ok = PK11SDR_Decrypt(&input, &output, NULL)

	if pwdcallcount > 1:
		NSS_Shutdown()
		raise NSSBadPassword("Decryption failed - bad password?")
	
	if not ok == 0:
		NSS_Shutdown()
		raise NSSError("Decryption failed, probably not because of bad password.")

	ok = NSS_Shutdown()

	if not ok == 0:
		raise NSSError("NSS_Shutdown failed.")

	retstring = PyString_FromStringAndSize( output.data, output.len)

	free( output.data )
	return retstring




def encrypt_pass(char *path, char* password, object string_to_crypt):
	cdef int ok
	
	set_password(password)
	ok = NSS_Init( path )

	if not ok == 0:
		raise NSSError("NSS_Init failed.")

	fixup_password()

	cdef  SECItem key
	cdef  SECItem input
	cdef  SECItem output

	input.data = PyString_AsString(string_to_crypt)
	input.len = len(string_to_crypt)
	input.type = 0

	output.type = 0
	output.len = 0 
	output.data = NULL

	key.type = 0
	key.len = 0 
	key.data = NULL

	ok = PK11SDR_Encrypt(&key, &input, &output, NULL)

	if pwdcallcount > 1:
		NSS_Shutdown()
		raise NSSBadPassword("Encryption failed - bad password?")
	
	if not ok == 0:
		NSS_Shutdown()
		raise NSSError("Encryption failed, probably not because of bad password.")

	ok = NSS_Shutdown()

	if not ok == 0:
		raise NSSError("NSS_Shutdown failed.")

	retstring = PyString_FromStringAndSize( output.data, output.len)

	free( output.data )
	return retstring

