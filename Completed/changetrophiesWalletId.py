
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0xF05624;         //需要hook的函数的偏移 0xF05624 public int get_KnowledgePoints() { }
    var struct_addr=0x0;  //0xF01580.0x78163d9540.0x6dbd0b9540
    var needpart=0xF8; //字段偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var field_addr;
    var arg0 = null;
    send("so基址："+n_addr_so);
    send("函数地址: " + nativePointer);
    
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            if(arg0==null){
            send("start....");
            send("struct_addr "+args[0]);
            field_addr = args[0].add(needpart);
            send("field_addr: " + field_addr);
            arg0=field_addr.readPointer();
            console.log(hexdump(arg0));
            send("hexdump:")
            arg0=arg0.add(0x14)
            send(arg0.readUtf16String());
            //写入id 未测试
            //arg0.writeUtf16String("61863d2b-18bf-43b6-b0ab-804c77b2d574");
            //把dump下的数据替换写入
            /*
            arg0.writeByteArray([0x00,0xcb,0x04,0x5e,0x70,0x00,0x00,0xb4,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                                  ,0x24,0x00,0x00,0x00,0x31,0x00,0x30,0x00,0x63,0x00,0x30,0x00,0x34,0x00,0x31,0x00
                                  ,0x64,0x00,0x61,0x00,0x2d,0x00,0x61,0x00,0x38,0x00,0x33,0x00,0x64,0x00,0x2d,0x00
                                  ,0x34,0x00,0x36,0x00,0x65,0x00,0x61,0x00,0x2d,0x00,0x39,0x00,0x64,0x00,0x31,0x00
                                  ,0x65,0x00,0x2d,0x00,0x39,0x00,0x33,0x00,0x65,0x00,0x66,0x00,0x35,0x00,0x64,0x00
                                  ,0x61,0x00,0x64,0x00,0x37,0x00,0x63,0x00,0x37,0x00,0x66,0x00,0x00,0x00,0x00,0x00]);
            */
            }
        }
            
        }
    );
    
    
    

    

});
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)

 #process = frida.get_remote_device().attach("Bloons TD 6")

str_host="192.168.104.205:1234"
manager=frida.get_device_manager()
remote_device=manager.add_remote_device(str_host)
process= remote_device.attach("Bloons TD 6")

script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()