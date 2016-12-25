{
  "targets": [
    {
      "target_name": "freefare",
      "sources": [ "freefare.cc" ],
      "link_settings":
      {
        "libraries": [ "/usr/lib/libnfc.so","/usr/lib/libfreefare.so" ],
        "include_dirs": [ "include", "/usr/include/nfc"]
      }
    }
  ]
}