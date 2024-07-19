def create_matrix(rails, text):
	matrix = [['*' for i in range(len(text))] for j in range(rails)]
	row = 0
	direction = 1  # 1 -> uvecaj, -1 -> smanjuj
	for index, char in enumerate(text):
		matrix[row][index] = char
		row += direction
		if row < 0 or row == rails:
			direction *= -1
			row += 2*direction
	return matrix
def encrypt(rails, text):
	text = text.lower().replace(" ", "")
	matrix = create_matrix(rails, text)
	cipher = ""
	for i in range(rails):
		for x in matrix[i]:
			if x != '*':
				cipher += x
	return cipher
