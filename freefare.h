#include <node.h>
/*
* NFC Library and Free Fare Library
*/
#include <nfc/nfc.h>
#include <freefare.h>
using namespace v8;

//
// C Library Variables
//
static int error = 0;
static nfc_device *device = NULL;
static MifareTag *tags = NULL;
static Mad mad;



