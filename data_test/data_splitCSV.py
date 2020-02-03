import csv
import statistics as stat
import numpy as np
import pandas as pd
from random import randrange
import sys, getopt

## X will be splitted in x1 and x2 where x1+x2=X
def create_shares_of_value(valueToShare):
    random = randrange(8)
    
    result = []
    oneShare = valueToShare - random
    twoShare = random
    result.append(oneShare)
    result.append(twoShare)
    

    
    return result


def main(argv):
    
		loc = './example_route_cleaned.csv'
		try:
				opts, args = getopt.getopt(argv,"hf:",["file="])
		except getopt.GetoptError:
			print ('dataSplitCSV.py -f <file>')
			sys.exit(2)
		for opt, arg in opts:
			if opt == '-h':
				print ('dataSplitCSV.py -f <file>')
				sys.exit()
			elif opt in ("-f", "--file"):
				loc = str(arg)
			else:
				print('ERROR.py -f <file>')
				
				

		##Creating a list
		##each pair x11 x12 y11 y12 are just one set of coordinates
		x1_s1 =[] 
		x1_s2 =[] 

		x2_s1 =[] 
		x2_s2 =[] 

		y1_s1 =[] 
		y1_s2 =[] 

		y2_s1 =[] 
		y2_s2 =[] 
		
		
		df = pd.read_csv(loc, header = None)#,names=["X_START", "Y_START", "X_END", "Y_END"])
		print(df)
		x_start = df.iloc[:,0]
		y_start = df.iloc[:,1]
		x_end = df.iloc[:,2]
		y_end = df.iloc[:,3]


		row_count = sum(1 for row in x_start)
		
		
		print(x_start)
		for row in x_start:
			shares = create_shares_of_value(row)
			x1_s1.append(shares[0])
			x1_s2.append(shares[1])
		for row in x_end:
			shares = create_shares_of_value(row)
			x2_s1.append(shares[0])
			x2_s2.append(shares[1])
		for row in y_start:
			shares = create_shares_of_value(row)
			y1_s1.append(shares[0])
			y1_s2.append(shares[1])
		for row in y_end:
			shares = create_shares_of_value(row)
			y2_s1.append(shares[0])
			y2_s2.append(shares[1])
		
		
		
		fileOutput1= "data1.csv"
		fileOutput2= "data2.csv"

		dict1 = {'X_start': x1_s1, 'Y_START': y1_s1, 'X_END': x2_s1, "Y_END": y2_s1} 
		dict2 = {'X_start': x1_s2, 'Y_START': y1_s2, 'X_END': x2_s2, "Y_END": y2_s2} 

		df = pd.DataFrame(dict1)
		df.to_csv(fileOutput1, sep=',')
			
		df = pd.DataFrame(dict2)
		df.to_csv(fileOutput2, sep=',')

		

			
                
                
                
                
if __name__ == "__main__":
  main(sys.argv[1:])

     
