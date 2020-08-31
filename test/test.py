class Hello():
    def __init__(self):
        print("init")

    def public_method(self):
        print("public")
        self.__private_method()

    def __private_method(self):
        print("private")


class inh(Hello):
    def test(self):
        self.public_method()

i = inh()
i.test()