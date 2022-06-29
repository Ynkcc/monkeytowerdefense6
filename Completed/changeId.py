
import frida, sys
 
jsCode = """
Java.perform(function () {

    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset = 0xF05624;         //需要hook的函数的偏移 0xF05624 public int get_KnowledgePoints() { }
    var struct_addr = 0x0;  //0xF01580.0x78163d9540.0x6dbd0b9540
    var needpart = 0xF8; //字段偏移
    var needpart1 = 0xF0; //字段偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var field_addr;
    var field_addr1;
    var arg0 = null;
    var arg1 = null;
    send("so基址：" + n_addr_so);
    send("函数地址: " + nativePointer);


    var fun_offset = 0x2476514;
    var fun_func = parseInt(n_addr_so, 16) + fun_offset;
    var fun_Pointer = new NativePointer(fun_func);
    var fun = new NativeFunction(fun_Pointer, 'pointer', ["int"]);

    Interceptor.attach(nativePointer, {
        onEnter: function (args) {
            if (arg0 == null) {
                send("start....");
                send("struct_addr " + args[0]);
                field_addr = args[0].add(needpart);
                send("field_addr: " + field_addr);
                arg0 = field_addr.readPointer();


                field_addr1 = args[0].add(needpart1);
                send("field_addr1: " + field_addr1);
                arg1 = field_addr1.readPointer();

                arg0 = arg0.add(0x14)
                send(arg0.readUtf16String());
                send(hexdump(arg1))
                send(arg1.add(0x14).readUtf16String());

                //写入id 1开0关
                if (0) {
                    var ownerID = "no_link56c667c28721d17aaf47f67b0d9d18e2";
                    var trophiesWalletId = "10702c33-9340-4d99-ba84-953993591050";
                    arg0.writeUtf16String(trophiesWalletId);
                    var trophyStoreId = fun(120);
                    trophyStoreId.add(0x10).writeInt(ownerID.length);
                    trophyStoreId.add(0x14).writeUtf16String(ownerID);
                    field_addr1.writePointer(trophyStoreId);
                }

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

str_host="192.168.14.134:1234"
manager=frida.get_device_manager()
remote_device=manager.add_remote_device(str_host)
process= remote_device.attach("Bloons TD 6")

script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()