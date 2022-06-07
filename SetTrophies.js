Java.perform(function () {

    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    /*
    RVA: 0xF05624 Offset: 0xF05624 VA: 0xF05624
    public int get_KnowledgePoints() { }
    */
    var n_addr_func_offset = 0xF05624;         //需要hook的函数的偏移
    var struct_addr;
    var trophies = 0x140;   //字段偏移 public KonFuze trophies; // 0x140
    var trophiesWalletId = 0xF8; //public string trophiesWalletId; // 0xF8
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var trophies_addr;
    var trophiesWalletId_addr;
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

    Interceptor.attach(nativePointer, {
        onEnter: function (args) {
            if (arg0 == null) {
                send("start....");
                send("struct_addr " + args[0]);
                field_addr = args[0].add(needpart);
                send("field_addr: " + field_addr);
                send(args[1]);
                //send("args1:"+hexdump(args[1]));
                if (0) {
                    send('RegisterNatives called from:');
                    send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
                    send('----------------------------------------------------------------------------------------------')
                };

                send(args[2]);
                send(args[3]);
                send(args[4]);
            }
        },
        onLeave: function (retval) {
            if (arg0 == null) {
                send("retval:" + retval);
                if (retval.toInt32() == 25536) {
                    send('RegisterNatives called from:');
                    send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
                    send('----------------------------------------------------------------------------------------------')
                };
                send("hexdump:")
                console.log(hexdump(field_addr, { offset: 0, length: 400, header: true, ansi: false }));
                arg0 = field_addr.readPointer();
                send("arg0: " + arg0);
                send("over.....")
                send("get_val: " + get_val(arg0))
                set_val(arg0, 40000)
                send("get_val: " + get_val(arg0))
            }

        }
    });

});