import random as rdm
import csv

coeffs = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
with open('trainingset2.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    for _ in range(100000):
        l=[]
        for i in range(9):
            l.append(10*(0.5-rdm.random()))
        l.append(sum([coeffs[i]*l[i] for i in range(9)])+coeffs[9])
        writer.writerow(l)
