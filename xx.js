send("hexdump:" + hexdump(args[1], {
    offset: 0,
    length: 100,
    header: true,
    ansi: false
}));
