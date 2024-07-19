def process_key(key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    key = key.lower()
    num = 0
    positions = [None] * len(key)
    for i in alphabet:
        control = 0  # prati pojavljivanje karaktera
        for index, char in enumerate(key):  # enumerate vraca karakter i njegovu poziciju u stringu
            if i == char:
                control = 1
                positions[index] = num
        if control == 1:  # uvecava se samo ako je nadjen karakter u kljucu
            num += 1
    return positions


def find_counts_and_positions(positions):
    organized = {}
    for index, elem in enumerate(positions):
        if elem not in organized:
            organized[elem] = {"position": [], "count": 0}
        organized[elem]["count"] += 1
        organized[elem]["position"].append(index)
    return organized


def text_box(positions, text):
    text = text.lower().replace(" ", "")
    rows = len(text) // len(positions)
    if (len(text) % len(positions)) != 0: rows = rows + 1
    box = [[None for x in range(len(positions))] for y in range(rows)]
    for i in range(rows):
        for j in range(len(positions)):
            if len(text) > 0:
                box[i][j] = text[0]
                text = text[1:]
    return box, rows, len(positions)


def encrypt(key, text):
    positions = process_key(key)
    box, rows, cols = text_box(positions, text)
    cipher = ""
    info = find_counts_and_positions(positions)
    counter = 0
    for _ in info:
        for i in range(rows):
            for x in info[counter]["position"]:
                if box[i][x] is not None:
                    cipher += box[i][x]
        counter += 1
    return cipher

# print(encrypt("enkripcija", "ASIMETRICNI KRIPTOALGORITMI KORISTE PAR KLJUCEVA"))
