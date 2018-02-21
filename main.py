import collections
import sys
#при шифровании ключом 0 русские корректно, а английские сдвигаются за счёт того, что разная длина алфавита
Language = collections.namedtuple('Language', 'alphabet most_popular_letter')

class Dictionary:
    def __init__(self):
        self.RU = Language(alphabet = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя', most_popular_letter = 'о')
        self.EN = Language(alphabet = 'abcdefghijklmnopqrstuvwxyz', most_popular_letter = 'e')

    def is_letter(self, letter):
        return letter.lower() in self.RU.alphabet# + self.EN.alphabet

    def get_all_letters(self, text):
        return list(filter(lambda x: self.is_letter(x), text))

class Cipher:
    def __init__(self):
        self.dictionary = Dictionary()

    def shift_to_offset(self, letter, offset):
        if letter.lower() in self.dictionary.RU.alphabet:
            alphabet = self.dictionary.RU.alphabet
        #elif letter.lower() in self.dictionary.EN.alphabet:
        #    alphabet = self.dictionary.EN.alphabet
        else:
            return letter
        if letter.isupper():
            alphabet = alphabet.upper()
        return alphabet[(alphabet.find(letter) + offset) % len(alphabet)]

    def _crypt(self, text, key, is_encrypt):
        return ''.join([self.shift_to_offset(str(letter), key if is_encrypt else -key) for letter in text])

    def encrypt(self, text, key):
        return self._crypt(text, key, True)

    def decrypt(self, text, key):
        return self._crypt(text, key, False)

    def smart_decrypt(self, text):
        popular_letter = collections.Counter(self.dictionary.get_all_letters(text)).most_common(1)[0][0]
        if popular_letter in self.dictionary.RU.alphabet:
            alphabet = self.dictionary.RU.alphabet
            most_popular_letter = self.dictionary.RU.most_popular_letter
        elif popular_letter in self.dictionary.EN.alphabet:
            alphabet = self.dictionary.EN.alphabet
            most_popular_letter = self.dictionary.EN.most_popular_letter
        key = (alphabet.find(popular_letter) - alphabet.find(most_popular_letter)) % len(alphabet)
        sys.stdout.write(f'Popular letter in language: {most_popular_letter}\nPopular letter in secret text: {popular_letter}\nKey: {key}\n')
        return self.decrypt(text, key)


class FileEncrypter:
    def __init__(self, filename):
        self.cipher = Cipher()
        self.plain = filename
        self.secret = f'secret_{self.plain}'
        self.check = f'check_{self.plain}'

    def load_file(self, filename):
        self.plain = filename
        self.secret = f'secret_{self.plain}'
        self.check = f'check_{self.plain}'

    def encrypt_file(self, key):
        with open(self.plain, 'r') as plain, open(self.secret, 'w') as secret:
            plain_text = plain.read()
            filesize = len(plain_text)
            secret.write(self.cipher.encrypt(plain_text, key))
            #for i in range(filesize):
            #    secret.write(self.cipher.encrypt(plain_text[i], key))
            #    sys.stdout.write(f'\rEncryption progress: {(i / filesize) * 100:.2f}% ')
            #    sys.stdout.flush()
        sys.stdout.write('Encryption completed!\n')
        sys.stdout.flush()

    def smart_decrypt_file(self):
        with open(self.secret, 'r') as secret, open(self.check, 'w') as decrypt:
            decrypt.write(self.cipher.smart_decrypt(secret.read()))

    def compare_file(self):
        with open(self.plain, 'r') as original, open(self.check, 'r') as checked:
            original_text = self.cipher.dictionary.get_all_letters(original.read())
            checked_text = self.cipher.dictionary.get_all_letters(checked.read())
            different_letters = []
            position = 0
            for etalon, check in zip(original_text, checked_text):
                position += 1
                if check != etalon:
                    different_letters.append(f'{check} -> {etalon}')
                sys.stdout.write(f'\rComparing files: {(position / len(checked_text)) * 100:.2f}% ')
                sys.stdout.flush()
            sys.stdout.write(f'Incorrect characters in decrypted file: {(len(different_letters) / len(checked_text)) * 100:.2f}%\n')
            sys.stdout.flush()
            if different_letters:
                print(different_letters)

if __name__ == '__main__':
    file_encrypter = FileEncrypter('Kniga_shifrov.txt')
    file_encrypter.encrypt_file(153)
    file_encrypter.smart_decrypt_file()
    file_encrypter.compare_file()
    # file_encrypter = FileEncrypter('text.txt')
    # file_encrypter.encrypt_file(3)
    # file_encrypter.smart_decrypt_file()
    # file_encrypter.compare_file()
    #
    # file_encrypter.load_file('text_ru.txt')
    # file_encrypter.encrypt_file(7)
    # file_encrypter.smart_decrypt_file()
    # file_encrypter.compare_file()
    #
    # file_encrypter.load_file('text_en.txt')
    # file_encrypter.encrypt_file(18)
    # file_encrypter.smart_decrypt_file()
    # file_encrypter.compare_file()

