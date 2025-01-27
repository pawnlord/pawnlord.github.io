# x3ctf
Challenge write ups for x3ctf

## submission (web)
### hint
```
Could you help us out?
 - by rebane2001
```
This was an easy web that stumped us for a little bit. It's a PHP file server, where files sent are "chmod"ed to be invisible
### the layout
The important bit of code is here:
```js
if (isset($_FILES['file'])) {
    $uploadOk = 1;
    $target_dir = "/var/www/html/uploads/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    echo $target_file

    if (file_exists($target_file)) {
        echo "Sorry, file already exists.";
        $uploadOk = 0;
    }
    if ($_FILES["file"]["size"] > 50000) {
        echo "Sorry, your file is too large you need to buy Nitro.";
        $uploadOk = 0;
    }
    if (!str_ends_with($target_file, '.txt')) {
        echo "Due to exploit you can only upload files with .txt extensions sorry about this but we got hacked last time so we have to check this from now on.";
        $uploadOk = 0;
    }i
    // Check if $uploadOk is set to 0 by an error
    if ($uploadOk == 0) {
        echo "Sorry, your file was not uploaded.";
    // if everything is ok, try to upload file
    } else {
        if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
            echo "The file ". htmlspecialchars( basename( $_FILES["file"]["name"])). " has been uploaded.";
        } else {
            echo "Sorry, there was an error uploading your file.";
        }
    }

    $old_path = getcwd();
    chdir($target_dir);
    // make unreadable
    shell_exec('chmod 000 *');
    chdir($old_path);
}
```
flag.txt is stored in the `uploads/` folder and is set to invisible by chmod in the docker init script.  
When a post request is sent with a file, PHP first puts this file into the tmp directory with a random name. It then copies over the file by using the filename set in the POST request and stored in the _FILES list.  
### wrong solutions
We went over a lot of the PHP standard library functions to try and find soemthing wrong with them. I'll go over a quick overview now:  
- **basename:** This takes the 'canonical filename' from the name. Essentially, if you give it `path/file.txt` as a name, it will return `file.txt`.
- **str\_ends\_with:** Checks that the second argument is the end of the first argument. This was exploitable due to it handling filenames differently from how file systems handle them, specifically, `b"file.php\x00.txt` would be unmodified by basename, but the actual file system would see that name as `file.php` which could lead to an RCE. However, basenbame removes null bytes so this is no longer exploitable.
- **file\_exists:** We eventually checked this function. Apparently it had RCE at one point due to [PHAR files](https://medium.com/@DGclasher/unveiling-vulnerabilities-achieving-remote-code-execution-through-file-inclusion-and-file-upload-165366ebdd16), but we don't control the protocol and it was already patched in earlier versions of PHP.
Generally, any exploit we tried involved pushing a malicious PHP file (or file with PHP that could be run, such as .htaccess) and trying to confuse `str_ends_with` into thinking it was a txt file. We got around the final chmod by making it a dot file (e.g., `.attack.php\x00.txt` for the null byte attack) as then it would not be listed by the wildcard.  

However, the starting code seems to be perfectly secure. Eventually, I started looking for other attack vectors besides file extension confusion, and found this.
### the right solution (wildcard injection)
The wildcard operator is a dumb operator, it has no information on the command that it is expanding for. If this command has flags that can be put arbitrarily, then it becomes possible to inject these flags by having files with the flags as a name. I decided to test this. If I uploaded a file named `test.txt` and `-v` and then ran `chmod 000 *` in the uploads folder in the docker container, the output would look like this:
```
mode of 'test.txt' changed from 0777 (rwxrwxrwx) to 0000 (---------)
```
This confirmed that the attack could be possible. I just needed to find a suitable flag for an attack vector. Looking at the help for chmod:
```
-c, --changes          like verbose but report only when a change is made
-f, --silent, --quiet  suppress most error messages
-v, --verbose          output a diagnostic for every file processed
    --no-preserve-root  do not treat '/' specially (the default)
    --preserve-root    fail to operate recursively on '/'
    --reference=RFILE  use RFILE's mode instead of MODE values
-R, --recursive        change files and directories recursively
    --help        display this help and exit
    --version     output version information and exit
```
If we could use `--reference=RFILE`, we could change the mode of flag.txt to something readable. Remember earlier how i said dot files don't get changed? well we can still use them as a reference. Testing this locally, it seemed that `--reference` worked even if it came after the `000` argument, which means we could use it for our exploit. The final exploit went like this:  
- Upload a file `.ref.txt`
- Upload a file `--reference=.ref.txt`
- Navigate to `/uploads/flag.txt`  

With that, we get the flag