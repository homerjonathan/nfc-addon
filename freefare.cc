#define BUILDING_NODE_EXTENSION
#include <node.h>
#include <string.h>
#include <stdlib.h>
#include <v8.h>
/*
* NFC Library and Free Fare Library
*/
#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include <freefare.h>
#include <uv.h>


using namespace v8;

static nfc_context *context;
static nfc_device *pnd = NULL;
const uint8_t uiPollNr = 20;
const uint8_t uiPeriod = 2;
static nfc_modulation nmModulations[2];
const size_t szModulations = 2;
nfc_target nt;
int res = 0;
// Used to Deal with Multiple Tags that can be read - We are just reading the first!
static int tagIndex = 0;
static bool tagValid = false;
static bool madValid = false;
static MifareTag *tags = NULL;
static Mad mad;
/*

    NFC Forum AID - Defaults to NFC Forum Can Be Changed!

*/
// function_cluster_code
// application_code
static MadAid mad_our_aid = {
    0x03,0xe1
};
/*

    Application Default Size 1

*/
static size_t our_aid_size = 1;
/*

    Public Key A value of NFC Forum sectors

*/
static MifareClassicKey mifare_classic_our_public_key_a = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};
/*

    Public Key B so we can lock our system up!

*/
static MifareClassicKey mifare_classic_our_public_key_b = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};
/*

    Public Key A value of NFC Forum sectors

*/
static MifareClassicKey mifare_classic_our_secret_key_a = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};
/*

    Secret Key B so we can lock our system up!

*/
static MifareClassicKey mifare_classic_our_secret_key_b = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};


MifareClassicKey default_keys[40];
MifareClassicKey default_keys_int[] = {
    { 0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
    { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
    { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
    { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
    { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
    { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }
};
int              format_mifare_classic_1k (MifareTag tag);
int              format_mifare_classic_4k (MifareTag tag);
int              try_format_sector (MifareTag tag, MifareClassicSectorNumber sector);


int format_mifare_classic_1k (MifareTag tag)
{
    for (int sector = 0; sector < 16; sector++) {
        if (!try_format_sector (tag, sector))
            return 0;
    }
    return 1;
}

int format_mifare_classic_4k (MifareTag tag)
{
    for (int sector = 0; sector < (32 + 8); sector++) {
        if (!try_format_sector (tag, sector))
            return 0;
    }
    return 1;
}

int try_format_sector (MifareTag tag, MifareClassicSectorNumber sector)
{
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
        MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);
        if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
            if (0 == mifare_classic_format_sector (tag, sector)) {
                mifare_classic_disconnect (tag);
                return 1;
            } else {
                return 0;
            }
            mifare_classic_disconnect (tag);
        }

        if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
            if (0 == mifare_classic_format_sector (tag, sector)) {
                mifare_classic_disconnect (tag);
                return 1;
            } else {
                return 0;
            }
            mifare_classic_disconnect (tag);
        }
    }
    return 0;
}

int try_authenticate_sector (MifareTag tag, MifareClassicBlockNumber block)
{
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
        if  (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A)) {
            // Success We Have Access
            return 1;
        }
        if (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B)) {
            // Success We Have Access
            return 1;
        }
    }
    return 0;
}

int try_authenticate_sector_secure (MifareTag tag, MifareClassicBlockNumber block)
{
    if  (0 == mifare_classic_authenticate (tag, block, mifare_classic_our_secret_key_b, MFC_KEY_B)) {
         // Success We Have Access
         return 1;
    }
    if  (0 == mifare_classic_authenticate (tag, block, mifare_classic_our_secret_key_a, MFC_KEY_A)) {
         // Success We Have Access
         return 1;
    }
    return 0;
}

void findTag(){
  // tagValid is reset everytime the Poll Detects a Card!
  bool error = false;
  if (tagValid == false)
  {
      tags = freefare_get_tags (pnd);
      if (tags) 
      {
           for (int i = 0; (!error) && tags[i]; i++)
           {
               switch (freefare_get_tag_type (tags[i]))
               {
                  case CLASSIC_1K:
                  case CLASSIC_4K:
                       break;
                  default:
                       continue;
               }
            // Classic Tag Found
            tagIndex = i;
            tagValid = true;
            madValid = false;
            return;
           }
      } else
      {
        tagIndex = 0;
        tagValid = false;
      }
  }
}

struct Baton {
    uv_work_t request;
    Persistent<Function> callback;
    int error_code;
    // Custom data
    int32_t result;
};
void AsyncWork(uv_work_t* req) {
    // No HandleScope!
    Baton* baton = static_cast<Baton*>(req->data);
    // Do work in threadpool here.
    // Set baton->error_code/message on failures.
    int res = 0;
    if (pnd != NULL)
    {
      if ((res = nfc_initiator_poll_target(pnd, nmModulations, szModulations, uiPollNr, uiPeriod, &nt))  < 0)
      {
        baton->result = 0;
      }
      else
      {
        baton->result = 1;
      }
    }
}

void AsyncAfter(uv_work_t* req, int status) {
    HandleScope scope;
    Baton* baton = static_cast<Baton*>(req->data);
    // Reset Tag Index
    tagValid = false;
    if (baton->result == 0) 
    {
       Local<Value> err = Exception::Error(String::New("ERROR"));
       Local<Value> argv[] = { err };
       TryCatch try_catch;
       // Call Batch
       baton->callback->Call(Context::GetCurrent()->Global(), 1, argv);
       if (try_catch.HasCaught())
       {
          node::FatalException(try_catch);
       }
    }
    else
    {
       Local<Value> argv[1];
       argv[0] = Local<Value>::New(String::New("NEWCARD"));
       TryCatch try_catch;
       // Call Batch
       baton->callback->Call(Context::GetCurrent()->Global(), 1, argv);
       if (try_catch.HasCaught())
       {
          node::FatalException(try_catch);
       }
    }
    baton->callback.Dispose();
    delete baton;
}

Handle<Value> openCard(const Arguments& args) {
    HandleScope scope;
    findTag();
    if (tagValid)
    {
        if (0 != mifare_classic_connect (tags[tagIndex]))
        {
            // Something Went Wrong!
            madValid = false;
            return scope.Close(v8::String::New("ERROR - Not Connected to Card"));
        }
        else
        {
            // Open Connection to Card
            if ((mad = mad_read (tags[tagIndex]))) {
               madValid = true;
               return scope.Close(v8::String::New("OK"));
            }
            else
            {
               return scope.Close(v8::String::New("ERROR - No Mifare Directory Found"));
            }
        }
    }
    return scope.Close(v8::String::New("ERROR"));
}


Handle<Value> OnCard(const Arguments& args) {
    HandleScope scope;
    // Reset Tag Valid
    tagValid = false;
    // Call Back Function
    if (!args[0]->IsFunction()) {
        return ThrowException(Exception::TypeError(String::New(
            "First argument must be a callback function")));
    }
    Local<Function> callback = Local<Function>:: Cast(args[0]);
    //
    // Do Poll
    //
    Baton* baton = new Baton();
    baton->request.data = baton;
    baton->callback = Persistent<Function>::New(callback);
    uv_queue_work(uv_default_loop(), &baton->request, AsyncWork, AsyncAfter);
    return scope.Close(v8::String::New("OK - Asynchonous Monitoring Of Port"));
}

Handle<Value> nfc_start(const Arguments& args) {
  HandleScope scope;
  // Array Creation - For cards we are detecting - Mifare Classic!  Alter here if you want to expand the range!
  nfc_modulation mod1;
  mod1.nmt = NMT_ISO14443A;
  mod1.nbr = NBR_106;
  nmModulations[0] = mod1;
  nfc_modulation mod2;
  mod2.nmt = NMT_ISO14443B;
  mod2.nbr = NBR_106;
  nmModulations[1] = mod2;

  // Configure the Key
  memcpy(default_keys, default_keys_int, sizeof(default_keys_int));
  // Do NFC Init In Here!
  nfc_init (&context);
  if (context == NULL)
  {
       return scope.Close(v8::String::New("ERROR"));
  }
  // Open Device
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    nfc_exit(context);
    return scope.Close(v8::String::New("ERROR"));
  }
  return scope.Close(v8::String::New("OK"));
  return scope.Close(Undefined());
}
//
// Assumes that Smartcard/Tag is there and ready to read. Returns the ID
//
Handle<Value> getTag(const Arguments& args) {
  HandleScope scope;
  findTag();
  if (tagValid)
  {
      char *tag_uid = freefare_get_tag_uid (tags[tagIndex]);
      return scope.Close(v8::String::New(tag_uid));
  }
  else
  {
      return scope.Close(v8::String::New("ERROR"));
  }
}
//
// Close Connection to the RFID Reader
//
Handle<Value> nfc_stop(const Arguments& args) {
  HandleScope scope;
  // Do NFC Init In Here!
  if (pnd != NULL) {
     nfc_close(pnd);
  }
  if (context != NULL) {
     nfc_exit(context);
     return scope.Close(v8::String::New("OK"));
  }
  return scope.Close(v8::String::New("ERROR"));
}

Handle<Value> nfc_poll(const Arguments& args) {
  HandleScope scope;
  if (pnd != NULL) {
     if ((res = nfc_initiator_poll_target(pnd, nmModulations, szModulations, uiPollNr, uiPeriod, &nt))  < 0) {
        return scope.Close(v8::String::New("ERROR POLLING!"));
     }
     if (res > 0) {
       char *s;
       str_nfc_target(&s, &nt, 1);
       MifareTag *tags = NULL;
       tags = freefare_get_tags (pnd);
       if (!tags) {
         return scope.Close(v8::String::New("NO MIFARE"));
       }
       else {
         return scope.Close(v8::String::New("MIFARE Classic Found!"));
       }
     }
     else {
        return scope.Close(v8::String::New("ERROR POLLING!"));
     }
  }
  else {
      return scope.Close(v8::String::New("ERROR: Call function .start() first!"));
  }
}

Handle<Value> setMADFunctionCode(const Arguments& args) {
  HandleScope scope;
  if (args.Length() != 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }
  if (!args[0]->IsNumber() || !args[0]->IsInt32()) {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Integer between 0 and 255")));
    return scope.Close(Undefined());
  }
  // Convert Into Integer
  Local<Integer> num = Uint32::New(args[0]->IntegerValue());
  // Check if in range
  if ((num->Value() > 255) )
  {
    ThrowException(Exception::TypeError(String::New("Wrong arguments")));
    return scope.Close(Undefined());
  }
  // Good to go is a number and in range!
  mad_our_aid.function_cluster_code = (num->Value() & 0x000000ff);
  // Throw Value Back At Them!
  return scope.Close(num);
}

Handle<Value> setMADApplicationCode(const Arguments& args) {
  HandleScope scope;
  if (args.Length() != 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }
  if (!args[0]->IsNumber() || !args[0]->IsInt32()) {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Integer between 0 and 255")));
    return scope.Close(Undefined());
  }
  // Convert Into Integer
  Local<Integer> num = Uint32::New(args[0]->IntegerValue());
  // Check if in range
  if ((num->Value() > 255) )
  {
    ThrowException(Exception::TypeError(String::New("Wrong arguments")));
    return scope.Close(Undefined());
  }
  // Good to go is a number and in range!
  mad_our_aid.application_code = (num->Value() & 0x000000ff);
  // Throw Value Back At Them!
  return scope.Close(num);
}

Handle<Value> setMADApplicationSize(const Arguments& args) {
  HandleScope scope;
  if (args.Length() != 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }
  if (!args[0]->IsNumber() || !args[0]->IsInt32()) {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Integer between 0 and 255")));
    return scope.Close(Undefined());
  }
  // Convert Into Integer
  Local<Integer> num = Uint32::New(args[0]->IntegerValue());
  // Check if in range
  if ((num->Value() > 255) )
  {
    ThrowException(Exception::TypeError(String::New("Wrong arguments")));
    return scope.Close(Undefined());
  }
  // Good to go is a number and in range!
  our_aid_size = (num->Value() & 0x000000ff);
  // Throw Value Back At Them!
  return scope.Close(num);
}

Handle<Value> setMifareData(const Arguments& args) {
  HandleScope scope;
  if (args.Length() != 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }
  if (!args[0]->IsArray()) {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Array")));
    return scope.Close(Undefined());
  }
  // Convert into local array!
  Local<Array> obj = Local<Array>::Cast(args[0]);
  int length = obj->Get(v8::String::New("length"))->ToObject()->Uint32Value();
  unsigned char dataOut[length];
  for(int i = 0; i < length; i++)
  {
     v8::Local<v8::Value> element = obj->Get(i);
     if (element->IsNumber())
     {
        Local<Integer> num = Uint32::New(element->IntegerValue());
        dataOut[i] = (num->Value() & 0x000000ff);
     }
     // do something with element
  }
  // Now Write The Data
   if (length != mifare_application_write (tags[tagIndex], mad, mad_our_aid, dataOut, length, mifare_classic_our_public_key_b, MFC_KEY_B)) {
         return scope.Close(String::New("Error: Not Written Correctly"));
   }
  // Throw Value Back At Them!
  return scope.Close(v8::Integer::New(length));
}

Handle<Value> setSecureMifareData(const Arguments& args) {
   HandleScope scope;
   if (args.Length() != 1) {
     ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
     return scope.Close(Undefined());
   }
   if (!args[0]->IsArray()) {
     ThrowException(Exception::TypeError(String::New("Error: Should be an Array")));
     return scope.Close(Undefined());
   }
   // Convert into local array!
   Local<Array> obj = Local<Array>::Cast(args[0]);
   int length = obj->Get(v8::String::New("length"))->ToObject()->Uint32Value();
   unsigned char dataOut[length];
   for(int i = 0; i < length; i++)
   {
      v8::Local<v8::Value> element = obj->Get(i);
      if (element->IsNumber())
      {
         Local<Integer> num = Uint32::New(element->IntegerValue());
         dataOut[i] = (num->Value() & 0x000000ff);
      }
      // do something with element
   }
   // Now Write The Data
    if (length != mifare_application_write (tags[tagIndex], mad, mad_our_aid, dataOut, length, mifare_classic_our_secret_key_b, MFC_KEY_B)) {
          return scope.Close(String::New("Error: Not Written Correctly"));
    }
   // Throw Value Back At Them!
   return scope.Close(v8::Integer::New(length));
 }

Handle<Value> setSecureKeyA(const Arguments& args) {
  HandleScope scope;
  if (args.Length() != 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }
  if (!args[0]->IsArray()) {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Array of 6 bytes")));
    return scope.Close(Undefined());
  }
  // Convert into local array!
  Local<Array> obj = Local<Array>::Cast(args[0]);
  int length = obj->Get(v8::String::New("length"))->ToObject()->Uint32Value();
  if (length != 6)
  {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Array of 6 bytes")));
    return scope.Close(Undefined());
  }
  // Update Secret Key!
  for(int i = 0; i < length; i++)
  {
     v8::Local<v8::Value> element = obj->Get(i);
     if (element->IsNumber())
     {
        Local<Integer> num = Uint32::New(element->IntegerValue());
        mifare_classic_our_secret_key_a[i] = (num->Value() & 0x000000ff);
     }
     // do something with element
  }
  return scope.Close(String::New("OK"));
}

Handle<Value> setSecureKeyB(const Arguments& args) {
  HandleScope scope;
  if (args.Length() != 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }
  if (!args[0]->IsArray()) {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Array of 6 bytes")));
    return scope.Close(Undefined());
  }
  // Convert into local array!
  Local<Array> obj = Local<Array>::Cast(args[0]);
  int length = obj->Get(v8::String::New("length"))->ToObject()->Uint32Value();
  if (length != 6)
  {
    ThrowException(Exception::TypeError(String::New("Error: Should be an Array of 6 bytes")));
    return scope.Close(Undefined());
  }
  // Update Secret Key!
  for(int i = 0; i < length; i++)
  {
     v8::Local<v8::Value> element = obj->Get(i);
     if (element->IsNumber())
     {
        Local<Integer> num = Uint32::New(element->IntegerValue());
        mifare_classic_our_secret_key_b[i] = (num->Value() & 0x000000ff);
     }
     // do something with element
  }
  return scope.Close(String::New("OK"));
}

Handle<Value> getMADDir(const Arguments& args) {
   HandleScope scope;
   if (mad != NULL)
   {
     v8::Handle<v8::Object> external_array = v8::Object::New();
     external_array->SetIndexedPropertiesToExternalArrayData(mad, v8::kExternalUnsignedByteArray, sizeof(mad));
     return scope.Close(external_array);
   }
   else
   {
     return scope.Close(Undefined());
   }
 }

Handle<Value> getMADEntry(const Arguments& args) {
  HandleScope scope;
  if (mad != NULL) {
    MifareClassicSectorNumber *sectors, *p;
  	sectors = p = mifare_application_find (mad, mad_our_aid);
  	if (sectors) {
  	    // Return First Sector - Can Expand to read all
  	    return scope.Close(v8::Integer::New(mifare_classic_sector_first_block(*p)));
  	}
  	else {
        return scope.Close(Undefined());
  	}
  }
  else {
    return scope.Close(Undefined());
  }
}

Handle<Value> deleteMADEntry(const Arguments& args) {
  HandleScope scope;
  if (mad != NULL) {
    int result = mifare_application_free (mad, mad_our_aid);
    if (result == 0) {
        // Good
        return scope.Close(v8::String::New("OK"));
    }
    else {
        // Problem Not Found Etc
        return scope.Close(v8::String::New("ERROR - Application Not Found"));
    }
  }
  else {
    return scope.Close(v8::String::New("ERROR: No MAD Found"));
  }
}

Handle<Value> createMADEntry(const Arguments& args) {
  HandleScope scope;
  if (mad != NULL) {
    MifareClassicSectorNumber *sectors, *p;
    sectors = p = mifare_application_alloc (mad, mad_our_aid, our_aid_size);
   	if (sectors) {
   	    // Good - Now Set Sector Rights.
   	    int s = 0;
        		while (sectors[s]) {
        		    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sectors[s]);
        		    MifareClassicBlock block_data;
        		    // Set Security Up for Sector - Default Open Key A and Open Key B
        		    mifare_classic_trailer_block (&block_data,  mifare_classic_our_public_key_a, 0x0, 0x0, 0x0, 0x6, 0x40, mifare_classic_our_public_key_b);
        		    if (try_authenticate_sector(tags[tagIndex],block) != 1) {
   	                    return scope.Close(v8::String::New("ERROR: Could Not Authenticate To Write Sector Key"));
        		    }
        		    if (mifare_classic_write (tags[tagIndex], block, block_data) < 0) {
   	                    return scope.Close(v8::String::New("ERROR: Write Failure"));
   	                }
        		    s++;
        		}
   	    return scope.Close(v8::String::New("OK"));
   	}
   	else {
   	    // Bad!
   	    return scope.Close(v8::String::New("ERROR: Not Created"));
   	}
    return scope.Close(v8::Integer::New(mifare_classic_sector_first_block(*p)));
  }
  else {
    return scope.Close(v8::String::New("ERROR: No MAD Found"));
  }
}

Handle<Value> createSecureMADEntry(const Arguments& args) {
  HandleScope scope;
  if (mad != NULL) {
    MifareClassicSectorNumber *sectors, *p;
    sectors = p = mifare_application_alloc (mad, mad_our_aid, our_aid_size);
   	if (sectors) {
   	    // Good - Now Set Sector Rights.
   	    int s = 0;
        		while (sectors[s]) {
        		    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sectors[s]);
        		    MifareClassicBlock block_data;
        		    // Set Security Up for Sector - Default Open Key A and Open Key B
        		    mifare_classic_trailer_block (&block_data,  mifare_classic_our_secret_key_a, 0x6, 0x6, 0x6, 0x6, 0x40, mifare_classic_our_secret_key_b);
        		    // First Try and Write Using Secure
        		    if (try_authenticate_sector_secure(tags[tagIndex],block) != 1) {
            		    // Now try standard keys
           		        if (try_authenticate_sector(tags[tagIndex],block) != 1) {
   	                        return scope.Close(v8::String::New("ERROR: Could Not Authenticate To Write Sector Key"));
        	    	    }
        		    }
        		    if (mifare_classic_write (tags[tagIndex], block, block_data) < 0) {
   	                    return scope.Close(v8::String::New("ERROR: Write Failure"));
   	                }
        		    s++;
        		}
   	    return scope.Close(v8::String::New("OK"));
   	}
   	else {
   	    // Bad!
   	    return scope.Close(v8::String::New("ERROR: Not Created"));
   	}
    return scope.Close(v8::Integer::New(mifare_classic_sector_first_block(*p)));
  }
  else {
    return scope.Close(v8::String::New("ERROR: No MAD Found"));
  }
}

Handle<Value> writeMADDir(const Arguments& args) {
  HandleScope scope;
  if (mad != NULL) {
    int result = mad_write (tags[tagIndex], mad, mifare_classic_our_public_key_b, mifare_classic_our_public_key_b);
    if (result == 0) {
        // Good
        return scope.Close(v8::String::New("OK"));
    }
    else {
        // Problem Not Found Etc
        return scope.Close(v8::String::New("ERROR - Application Not Found"));
    }
  }
  else {
    return scope.Close(v8::String::New("ERROR: No MAD Found"));
  }
}

Handle<Value> format(const Arguments& args) {
  HandleScope scope;
  if (tagValid == true) {
    // Sort Out Keys
    int error = 0;
    memcpy(default_keys, default_keys_int, sizeof(default_keys_int));
    enum mifare_tag_type tt = freefare_get_tag_type (tags[tagIndex]);
    switch (tt) {
                case CLASSIC_1K:
                    if (!format_mifare_classic_1k (tags[tagIndex]))
                        error = 1;
                    break;
                case CLASSIC_4K:
                    if (!format_mifare_classic_4k (tags[tagIndex]))
                        error = 1;
                    break;
                default:
                    /* Keep compiler quiet */
                    break;
                        // Unknown Card Format
                        error = 1;
                }
    if (error == 1) {
        return scope.Close(v8::String::New("ERROR: Formatting Card (Card moved out of range or Faulty!"));
    } else {
        return scope.Close(v8::String::New("OK"));
    }
  }
  else {
    return scope.Close(v8::String::New("ERROR: Not Connected"));
  }
}



Handle<Value> getMifareData(const Arguments& args) {
  HandleScope scope;
  if (mad != NULL)
  {
    uint8_t buffer[4096];
  	ssize_t len;

    if ((len = mifare_application_read (tags[tagIndex], mad, mad_our_aid,
                                      buffer, sizeof(buffer),
                                      mifare_classic_our_public_key_a, MFC_KEY_A)) != -1)
    {
            v8::Handle<v8::Object> external_array = v8::Object::New();
            external_array->SetIndexedPropertiesToExternalArrayData(buffer, v8::kExternalUnsignedByteArray, len);
            return scope.Close(external_array);
    }
    else
    {
        // Something went wrong!
        return scope.Close(Undefined());
    }
  }
  else
  {
    // Something Went Wrong - No MAD
    return scope.Close(Undefined());
  }
}

Handle<Value> getSecureMifareData(const Arguments& args) {
  HandleScope scope;
  if (mad != NULL)
  {
    uint8_t buffer[4096];
  	ssize_t len;

    if ((len = mifare_application_read (tags[tagIndex], mad, mad_our_aid,
                                      buffer, sizeof(buffer),
                                      mifare_classic_our_secret_key_b, MFC_KEY_B)) != -1)
    {
            v8::Handle<v8::Object> external_array = v8::Object::New();
            external_array->SetIndexedPropertiesToExternalArrayData(buffer, v8::kExternalUnsignedByteArray, len);
            return scope.Close(external_array);
    }
    else
    {
        // Something went wrong!
        return scope.Close(Undefined());
    }
  }
  else
  {
    // Something Went Wrong - No MAD
    return scope.Close(Undefined());
  }
}
//
// Declare Functions for my Library
//
void Init(Handle<Object> exports) {
  // Export Start Function
  exports->Set(String::NewSymbol("start"),
      FunctionTemplate::New(nfc_start)->GetFunction());
  // Export Stop Function
  exports->Set(String::NewSymbol("stop"),
      FunctionTemplate::New(nfc_stop)->GetFunction());
  // Export Stop Function
  exports->Set(String::NewSymbol("poll"),
      FunctionTemplate::New(nfc_poll)->GetFunction());
  // Export On Card with Callback
  exports->Set(String::NewSymbol("OnCard"),
      FunctionTemplate::New(OnCard)->GetFunction());
  // Export GetTag
  exports->Set(String::NewSymbol("getTag"),
      FunctionTemplate::New(getTag)->GetFunction());
  // Export Open Connection to Card
  exports->Set(String::NewSymbol("openCard"),
      FunctionTemplate::New(openCard)->GetFunction());
  // Export Mifare Application Directory (MAD)
  exports->Set(String::NewSymbol("getMADDir"),
      FunctionTemplate::New(getMADDir)->GetFunction());
  // Export Set MAD Function Code
  exports->Set(String::NewSymbol("setMADFunctionCode"),
      FunctionTemplate::New(setMADFunctionCode)->GetFunction());
  // Export Set MAD Application Code
  exports->Set(String::NewSymbol("setMADApplicationCode"),
      FunctionTemplate::New(setMADApplicationCode)->GetFunction());
  // Export Set MAD Application Size
  exports->Set(String::NewSymbol("setMADApplicationSize"),
      FunctionTemplate::New(setMADApplicationSize)->GetFunction());
  // Export Get MAD Entry Cluster for Our Application
  exports->Set(String::NewSymbol("getMADEntry"),
      FunctionTemplate::New(getMADEntry)->GetFunction());
  // Export Create MAD Entry for Our Application
  exports->Set(String::NewSymbol("createMADEntry"),
      FunctionTemplate::New(createMADEntry)->GetFunction());
  // Export Create MAD Entry for Our Application
  exports->Set(String::NewSymbol("createSecureMADEntry"),
      FunctionTemplate::New(createSecureMADEntry)->GetFunction());
  // Export Delete MAD Entry for Our Application
  exports->Set(String::NewSymbol("deleteMADEntry"),
      FunctionTemplate::New(deleteMADEntry)->GetFunction());
  // Export Write MAD Directory of Card
  exports->Set(String::NewSymbol("writeMADDir"),
      FunctionTemplate::New(writeMADDir)->GetFunction());
  // Export Get Mifare Data
  exports->Set(String::NewSymbol("getMifareData"),
      FunctionTemplate::New(getMifareData)->GetFunction());
  // Export Get Mifare Data
  exports->Set(String::NewSymbol("setMifareData"),
      FunctionTemplate::New(setMifareData)->GetFunction());
  // Export Get Secure Mifare Data
  exports->Set(String::NewSymbol("getSecureMifareData"),
      FunctionTemplate::New(getSecureMifareData)->GetFunction());
  // Export Get Secure Mifare Data
  exports->Set(String::NewSymbol("setSecureMifareData"),
      FunctionTemplate::New(setSecureMifareData)->GetFunction());
  // Export Set Secure Key A
  exports->Set(String::NewSymbol("setSecureKeyA"),
      FunctionTemplate::New(setSecureKeyA)->GetFunction());
  // Export Set Secure Key B
  exports->Set(String::NewSymbol("setSecureKeyB"),
      FunctionTemplate::New(setSecureKeyB)->GetFunction());
  // Export Format
  exports->Set(String::NewSymbol("format"),
      FunctionTemplate::New(format)->GetFunction());
}
// Macro to hook into node.js
NODE_MODULE(freefare, Init)