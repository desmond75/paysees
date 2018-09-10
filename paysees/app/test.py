# import sqlite3 as sq
# import time

# db = sq.connect('neola.db')

# conn = db.cursor()
# #conn.execute('DROP TABLE neola')



# #conn.execute('CREATE TABLE  IF NOT EXISTS neola  (name text, age integer ,quater text)')


# # conn.execute('INSERT INTO neola (name, age, quater) VALUES(?,?,?)',('Neola',24,'Ngulung'))
# # conn.execute('INSERT INTO neola (name, age, quater) VALUES(?,?,?)',('Ade',24,'Ntanbeng'))
# x = 'Ade'
# conn.execute('SELECT *  FROM neola WHERE name= ?',(x,))
# c = conn.fetchone()
# print c[0]
# if c[0] == 'Ade':
# 	print 'Duplicte found'
# else:
# 	print 'no Duplicate found'


import random 



def strong_password():


	letters= 'A	B	C	D	E	F	G	H	I	J	K	L	M	N	O	P	Q	R	S	T	U	V	W	X	Y	Z'.split()
	number = [0,1,2,3,4,5,6,7,8,9]

	" picks random letter in letters"
	f1 = random.choice(letters)
	f2 = random.choice(letters)
	f3 = random.choice(letters)
	f4 = random.choice(letters)

	num1 = random.choice(number)
	num2 = random.choice(number)


	'initialize password to an empty string'
	password = ''

	'adds the random pick letters to password'
	password+=f1
	password+=str(num2)
	password+=f2
	password += str(num1)
	password+=f3
	password+=f4
	
	return password



print(strong_password())