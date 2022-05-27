

import frida, sys
 
jsCode = """
Java.perform(function(){
    var struct_addr= 0x6d45748540;  //0xF01580.0x78163d9540.0x6dbd0b9540
    var needpart=0x150 //×Ö¶ÎÆ«ÒÆ
    var n_addr_func = struct_addr + needpart;
    
    var momeryaddr=new NativePointer(n_addr_func);
    send("native: " + momeryaddr);
    send("hexdump:")
    console.log(hexdump(momeryaddr, { offset: 0, length: 400, header: true, ansi: false }));
    //send(momeryaddr.readUtf16String());
    //send(momeryaddr.writeByteArray([0x01]));
    //send(momeryaddr.writeInt(82));
    //var OnCollect = new NativeFunction(nativePointer, 'void',["int"]);
    //send("ok");
    //OnCollect(30);


});
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)

process = frida.get_remote_device().attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()