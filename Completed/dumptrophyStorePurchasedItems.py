
import frida, sys
 
jsCode = """
Java.perform(function () {

    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset = 0xF05624;         //需要hook的函数的偏移 0xF05624 public int get_KnowledgePoints() { }
    var struct_addr = 0x0;  //0xF01580.0x78163d9540.0x6dbd0b9540
    var needpart = 0x318; //字段偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var field_addr;
    var arg0 = null;
    send("so基址：" + n_addr_so);
    send("native: " + nativePointer);


    var getval_offset = 0xE5453C;     //需要hook的函数的偏移.0xE544E4.set.0xE5453C.get
    var setval_offset = 0xE544E4;
    var getval_func = parseInt(n_addr_so, 16) + getval_offset;
    var setval_func = parseInt(n_addr_so, 16) + setval_offset;
    var getval_Pointer = new NativePointer(getval_func);
    var setval_Pointer = new NativePointer(setval_func);
    var set_val = new NativeFunction(setval_Pointer, 'void', ["pointer", "double"]);
    var get_val = new NativeFunction(getval_Pointer, 'int', ["pointer"]);
    var resultval = null;

    Interceptor.attach(nativePointer, {
        onEnter: function (args) {
            if (field_addr == null) {
                send("start....");
                send("struct_addr " + args[0]);
                field_addr = args[0].add(needpart);
                send("field_addr: " + field_addr);
                var Dictaddr = field_addr.readPointer();
                var entriesaddr = Dictaddr.add(0x18)
                var entries = entriesaddr.readPointer();
                var aunit = entries.add(0x20);
                var i = 1;
                //0x18
                while (aunit.toInt32() != 0) {
                    send(i);
                    var Key = (aunit.add(0x8)).readPointer()
                    send((Key.add(0x14)).readUtf16String());
                    
                    aunit = aunit.add(0x18);
                    if (i == 1) {
                        send("Key:" + hexdump(Key));
                    }
                    i = i + 1;
                }
            }
        }
    });
});
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)
 
str_host="192.168.209.205:1234"
manager=frida.get_device_manager()
remote_device=manager.add_remote_device(str_host)
process= remote_device.attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()