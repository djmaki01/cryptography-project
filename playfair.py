def make_matrix(key):
    key = key.lower().replace("j", "i")
    # dictionary ne dozvoljava duplikate
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    key = dict.fromkeys(key)
    key = "".join(key)  # vraca ga u string
    matrix = []
    for char in key:
        matrix.append(char)
    for char in alphabet:
        if char not in key:
            matrix.append(char)
    final_matrix = [matrix[i:i + 5] for i in range(0, 25, 5)]  # pravi listu u listi; 2d;
    return final_matrix


def format_text(text):
    text = text.lower().replace("j", "i")
    text = text.replace(" ", "")
    formated_text = []
    i = 0
    while i < len(text):
        if i == len(text) - 1:  # ako je ostao neparan sam zadnji char
            formated_text.append(text[i] + "x")
            break
        elif text[i] == text[i + 1]:
            formated_text.append(text[i] + "x")
            i += 1
        else:
            formated_text.append(text[i] + text[i + 1])
            i += 2
    return formated_text


def where_in_matrix(char, matrix):
    for rows in range(5):
        for columns in range(5):
            if char == matrix[rows][columns]:
                return rows, columns


def encrypt(key, text):
    matrix = make_matrix(key)
    text = format_text(text)
    cipher = ""
    for i in text:
        row1, col1 = where_in_matrix(i[0], matrix)
        row2, col2 = where_in_matrix(i[1], matrix)
        if col1 == col2:
            cipher += matrix[(row1 + 1) % 5][col1]
            cipher += matrix[(row2 + 1) % 5][col2]
        elif row1 == row2:
            cipher += matrix[row1][(col1 + 1) % 5]
            cipher += matrix[row2][(col2 + 1) % 5]
        else:
            cipher += matrix[row1][col2]
            cipher += matrix[row2][col1]
    return cipher
