import linecache
import os
import bcrypt


class User:
	def __init__(self, username, password, first_name, last_name, email, country, state, city):
		users_path = linecache.getline("./path", 4).rstrip('\n')
		self.folder = os.path.join(users_path, username)
		# kreira folder ako vec ne postoji pod tim imenom ./users/username
		if not os.path.exists(self.folder):
			os.makedirs(self.folder)
		self.username = username
		self.file = self.create_file()
		self.password = self.hash_password(password)
		self.first_name = first_name
		self.last_name = last_name
		self.email = email
		self.country = country
		self.state = state
		self.city = city
		# self.priv_key = rsakey.generate(password.encode('utf-8'), self.folder)
		# self.certificate = certificate.generate(self, password)

	# pravi heš funkcije, blowfish, ima i salt
	def hash_password(self, password):
		return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
	
	def verify_password(self, password):
		return bcrypt.checkpw(password.encode(), self.password.encode())

	def create_file(self):
		with open(self.folder+"/simulation_history.txt", 'x') as file:
			pass
		return self.folder+"/simulation_history.txt"
