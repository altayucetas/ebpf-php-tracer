<?php
function foo($n) { 
    system("ls -la"); // execve syscall'ını tetikler
    file_get_contents("/etc/passwd"); // open syscall'ını tetikler
    $sock = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($sock) {
        @socket_bind($sock, '127.0.0.1', 5555);
        @socket_connect($sock, '8.8.8.8', 80);
        @socket_listen($sock, 1);
        @socket_close($sock);
    }
    //chmod("/tmp/output_renamed.txt", 0644);
    return bar($n - 1); 
}
function bar($n) { 
    if ($n <= 0) return 1; 
    shell_exec("echo 'Hello'"); // execve syscall'ını tetikler
    $f = fopen("/tmp/test.txt", "w"); // open syscall'ını tetikler
    @rmdir("/tmp/baz_dir");
    if ($f) fclose($f);
    return baz($n) + foo($n - 1); 
}

function baz($n) {
    usleep(10000);
    exec("pwd"); // execve syscall'ını tetikler
    @chown("/tmp/output_renamed.txt", 0);
    file_put_contents("/tmp/output.txt", "test"); // open syscall'ını tetikler

    // Dosya adını değiştir (rename syscall'ı tetikler)
    rename("/tmp/output213.txt", "/tmp/output_renamed.txt");

    return $n * 2; 
}

function kaz($n) { 
    //unlink("/tmp/output.txt");
    chmod("/tmp/output_renamed.txt", 0644);
    chmod("/tmp/output_skaldlkasjdals.txt", 0644);
    $uname = php_uname();
    echo $uname . "sada\n";
    return $n * 2; 
}

function kill() {
    $fake_pid = 26745;
    @posix_kill($fake_pid, 9);
}

function secret($n) {
    echo "Gizli fonksiyon calisti! (input: $n)\n";
    chmod("/tmp/output_renamed.txt", 0644);
    //unlink("/tmp/output.txt");
}

function secret2($n) {
    echo "Gizli fonksiyon calisti! (input: $n)\n";
    unlink("/tmp/output.txt");
    //unlink("/tmp/output2.txt");
}

function safe() {
    echo "Güvenli fonksiyon calisti!\n";
}

function read() {
    $f = fopen("/dev/urandom", "r");
    if ($f) {
        fread($f, 1000000);
        fclose($f);
    }
}

function patates() {
    chmod("/tmp/output_renamed.txt", 0644);
    file_put_contents("/tmp/output.txt", "test");
    file_put_contents("/tmp/output2.txt", "test");
    shell_exec("echo 'Hello'");
    
}

function secret3() {
    echo "Gizli fonksiyon calisti!\n";
    shell_exec("echo 'Hello'");
}

function new_syscall() {
    $fp = fopen("/tmp/bigfile", "w+");
    if ($fp) {
        ftruncate($fp, 1024 * 1024);
        fclose($fp);
        shell_exec("dd if=/dev/zero of=/tmp/bigfile bs=1M count=1");
        shell_exec("php -r '\$f = fopen(\"/tmp/bigfile\", \"r\"); mmap(\$f, 1024*1024, MAP_SHARED, PROT_READ, 0); fclose(\$f);'");
    }

    shell_exec("strace -e ptrace ls >/dev/null 2>&1");
}

for ($i = 0; $i < 3; $i++) {
    echo foo(2), "\n";
    secret3();
}

for ($i = 0; $i < 2; $i++) {
    patates();
}

kaz(1);
kill();

// clone3, wait4
new_syscall();
read();

echo "Bir sayi gir: ";
$input = (int)fgets(STDIN);
if ($input === 1337) {
    secret($input);
    secret($input);
    secret($input);
    secret($input);
    secret($input);
}

if ($input === 7331) {
    secret2($input);
    secret2($input);
    secret2($input);
    secret2($input);
    secret2($input);
}

if ($input === 42) {
    safe();
}

?>