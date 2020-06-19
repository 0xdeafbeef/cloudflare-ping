#What it can do
 - you can set ttl
 - you can set timeout
 - you can provide hostname/ip address for ping. Hostname resolving is faster than builtin ping provides.
 
# How to run it
```
cargo build --release
sudo setcap cap_net_raw+ep ./target/release/internship_application_systems
./target/release/internship_application_systems --help for details
```

If you get segfault when runnig release build,  
then is seems, that there some problems with `.cargo/config` file.   
All infromation about segfault in code comments.    
Try to recompile with this flag
```
RUSTFLAGS="-C target-cpu=native" cargo build --release
```
if it still doesn't work, then check on debug build :(

The code is tested under arch linux having kernel `5.4.34-1` installed and arch linux with kernel `4.20`.