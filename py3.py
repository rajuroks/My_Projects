f = open("file2.txt", "rb")
s = f.readlines()
f.close()
f = open("file21.txt", "wb")
#s.reverse()
#for item in s:
# print >> f, item
f.write (s[::-1])
f.close()

