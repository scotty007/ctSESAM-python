#!/usr/bin/python3
# -*- coding: utf-8 -*-

from hashlib import pbkdf2_hmac

small_letters = list('abcdefghijklmnopqrstuvwxyz')
big_letters = list('ABCDEFGHJKLMNPQRTUVWXYZ')
numbers = list('0123456789')
special_characters = list('#!"§$%&/()[]{}=-_+*<>;:.')
password_characters = small_letters + big_letters + numbers + special_characters
salt = "pepper"


def convert_bytes_to_password(hashed_bytes, length):
    number = int.from_bytes(hashed_bytes, byteorder='big')
    password = ''
    while number > 0 and len(password) < length:
        password = password + password_characters[number % len(password_characters)]
        number = number // len(password_characters)
    return password


def generate_password(master_password, domain):
    hash_string = domain + master_password
    hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'),
                               salt.encode('utf-8'), 4096)
    return convert_bytes_to_password(hashed_bytes, 10)


def run_cli():
    import getpass

    master_password = getpass.getpass(prompt='Masterpasswort: ')
    domain = input('Domain: ')
    while len(domain) < 1:
        print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
        domain = input('Domain: ')
    password = generate_password(master_password, domain)
    print('Passwort: ' + password)


def run_gui():
    import tkinter as tk

    class Application(tk.Frame):
        def __init__(self):
            super().__init__(master=None)
            self.pack()
            self.master.title('c\'t SESAM')
            self.master.resizable(width=False, height=False)

            pad = {'padx': 2, 'pady': 2}

            self._tk_master_password = tk.StringVar()
            tk.Label(master=self, text='Masterpasswort:') \
                .grid(column=0, row=0, sticky=tk.E, **pad)
            tk_entry = tk.Entry(master=self, textvariable=self._tk_master_password,
                                show='*')
            tk_entry.grid(column=1, row=0, **pad)
            tk_entry.focus_set()

            self._tk_domain = tk.StringVar()
            tk.Label(master=self, text='Domain:') \
                .grid(column=0, row=1, sticky=tk.E, **pad)
            tk.Entry(master=self, textvariable=self._tk_domain) \
                .grid(column=1, row=1, **pad)

            self._tk_password = tk.StringVar()
            tk.Label(master=self, text='Passwort:') \
                .grid(column=0, row=2, sticky=tk.E, **pad)
            tk.Label(master=self, textvariable=self._tk_password) \
                .grid(column=1, row=2, sticky=tk.W, **pad)

            tk.Button(master=self, text='BEENDEN', command=self.master.destroy) \
                .grid(column=0, row=3, sticky=tk.EW, **pad)
            self._tk_copy_button = tk.Button(master=self, text='KOPIEREN',
                                             command=self._copy_password,
                                             state=tk.DISABLED)
            self._tk_copy_button.grid(column=1, row=3, sticky=tk.EW, **pad)

            self._tk_master_password.trace_variable('w', self._generate_password)
            self._tk_domain.trace_variable('w', self._generate_password)

        def _generate_password(self, *_):
            master_password = self._tk_master_password.get()
            if master_password:
                domain = self._tk_domain.get()
                if domain:
                    password = generate_password(master_password, domain)
                    self._tk_password.set(password)
                    self._tk_copy_button['state'] = tk.NORMAL
                    return
            self._tk_password.set('')
            self._tk_copy_button['state'] = tk.DISABLED

        def _copy_password(self):
            self.clipboard_clear()
            self.clipboard_append(self._tk_password.get())

    Application().mainloop()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate domain passwords from your masterpassword.')
    parser.add_argument('-g', '--gui', action='store_const', const=True,
                        help='Run tkinter GUI.')
    args = parser.parse_args()

    if args.gui:
        run_gui()
    else:
        run_cli()
